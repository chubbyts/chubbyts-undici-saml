import { Buffer } from 'node:buffer';
import { inflateRawSync } from 'node:zlib';
import type { Profile } from '@node-saml/node-saml';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Element } from '@xmldom/xmldom';
import type { SamlAssertionIdStore } from './assertion-id-store.js';
import { createInMemorySamlAssertionIdStore } from './assertion-id-store.js';
import { InvalidSamlResponseError } from './error.js';
import type { IdpMetadata, IdpMetadataResolver } from './metadata.js';
import { assertNonNegative, isHttpUrl, isObject } from './util.js';

/**
 * The verified identity of a saml response: the subject (`nameId`), the assertion's attribute statement
 * (`attributes`), the authentication context class the identity provider asserts (`authnContextClassRef`, e.g. to
 * verify that a requested multi factor authentication actually happened) and the session related fields needed for a
 * later logout (`sessionIndex`).
 */
export type SamlIdentity = {
  nameId: string;
  nameIdFormat?: string;
  sessionIndex?: string;
  authnContextClassRef?: string;
  issuer: string;
  attributes: Record<string, unknown>;
};

/**
 * A verified logout request of the identity provider (identity provider initiated single logout): the principal
 * (`nameId`) and session (`sessionIndex`) to log out, and the request `id` the logout response refers to.
 */
export type SamlLogoutRequest = {
  id: string;
  nameId: string;
  nameIdFormat?: string;
  sessionIndex?: string;
};

export type LoginUrlResolver = (relayState: string) => Promise<string>;

export type SamlResponseVerifier = (samlResponse: string) => Promise<SamlIdentity>;

/**
 * The url of the identity provider's single logout location carrying the logout request for the given identity
 * (service provider initiated single logout), or `undefined` if the identity provider or the service provider has no
 * single logout location: the logout then only ends the local session.
 */
export type LogoutUrlResolver = (identity: SamlIdentity, relayState: string) => Promise<string | undefined>;

/**
 * Verifies the logout request within the given query string (`SAMLRequest`, `RelayState`, `SigAlg`, `Signature` as
 * received, http-redirect binding).
 */
export type LogoutRequestVerifier = (query: string) => Promise<SamlLogoutRequest>;

/**
 * The url of the identity provider's single logout location carrying the logout response to the given logout request.
 */
export type LogoutResponseUrlResolver = (
  logoutRequest: SamlLogoutRequest,
  relayState: string | undefined,
  success: boolean,
) => Promise<string>;

/**
 * Verifies the logout response within the given query string (`SAMLResponse`, `RelayState`, `SigAlg`, `Signature` as
 * received, http-redirect binding).
 */
export type LogoutResponseVerifier = (query: string) => Promise<void>;

export type SamlServiceProvider = {
  resolveLoginUrl: LoginUrlResolver;
  verifySamlResponse: SamlResponseVerifier;
  resolveLogoutUrl: LogoutUrlResolver;
  verifyLogoutRequest: LogoutRequestVerifier;
  resolveLogoutResponseUrl: LogoutResponseUrlResolver;
  verifyLogoutResponse: LogoutResponseVerifier;
};

export type AuthnContextComparison = 'exact' | 'minimum' | 'maximum' | 'better';

/**
 * The `RequestedAuthnContext` of the authn request: the authentication context classes (e.g.
 * `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`) the identity provider is asked to
 * authenticate the subject with, and how to compare them (default: `exact`).
 */
export type AuthnContext = {
  classRefs: Array<string>;
  comparison?: AuthnContextComparison;
};

export type SamlServiceProviderOptions = {
  entityId: string;
  assertionConsumerServiceUrl: string;
  singleLogoutServiceUrl?: string;
  clockTolerance?: number;
  maxAssertionAge?: number;
  identifierFormat?: string | null;
  forceAuthn?: boolean;
  wantAssertionsSigned?: boolean;
  wantAuthnResponseSigned?: boolean;
  validateInResponseTo?: 'never' | 'ifPresent' | 'always';
  authnContext?: AuthnContext;
  privateKey?: string;
  certificate?: string;
  signatureAlgorithm?: 'sha256' | 'sha512';
  decryptionKey?: string;
  assertionIdStore?: SamlAssertionIdStore;
};

const VALIDATE_IN_RESPONSE_TO: Record<'never' | 'ifPresent' | 'always', ValidateInResponseTo> = {
  never: ValidateInResponseTo.never,
  ifPresent: ValidateInResponseTo.ifPresent,
  always: ValidateInResponseTo.always,
};

const AUTHN_CONTEXT_COMPARISONS: ReadonlyArray<string> = ['exact', 'minimum', 'maximum', 'better'];

// sha1 is supported by node-saml, but deliberately not offered: it is broken for signatures
const SIGNATURE_ALGORITHMS: ReadonlyArray<string> = ['sha256', 'sha512'];

// the signature algorithms accepted within a signed http-redirect query (node-saml would accept any hash node knows)
const SIGNATURE_ALGORITHM_URIS: ReadonlySet<string> = new Set([
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
]);

const PROTOCOL_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:protocol';

// a deflated logout message within a query is a few hundred bytes: bound the inflated size (an adversarial query could
// otherwise inflate to megabytes before it is parsed)
const MAX_LOGOUT_MESSAGE_SIZE = 65_536;

// a logout message is delivered by a browser redirect right after it got issued: one issued longer ago is a replay. A
// signed logout message could otherwise be replayed for as long as the identity provider's key is trusted (the
// NotOnOrAfter of a logout request is optional and a logout response has none)
const MAX_LOGOUT_MESSAGE_AGE = 300;

// the error node-saml throws for an encrypted assertion without a decryption key: a configuration problem (of the
// service provider or the identity provider), not an invalid saml response
const MISSING_DECRYPTION_KEY_MESSAGE = 'No decryption key for encrypted SAML response';

type LogoutMessageType = 'SAMLRequest' | 'SAMLResponse';

type LogoutMessage = {
  // the signed parameters node-saml verifies the query signature for
  container: Record<string, string>;
  root: Element;
};

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value !== '';

const quote = (values: ReadonlyArray<string>): string => values.map((value) => `"${value}"`).join(', ');

const assertAuthnContext = (authnContext: AuthnContext): void => {
  if (
    !isObject(authnContext) ||
    !Array.isArray(authnContext.classRefs) ||
    authnContext.classRefs.length === 0 ||
    !authnContext.classRefs.every(isNonEmptyString)
  ) {
    throw new Error('Invalid authnContext: classRefs must be a non-empty array of non-empty strings');
  }

  if (authnContext.comparison !== undefined && !AUTHN_CONTEXT_COMPARISONS.includes(authnContext.comparison)) {
    throw new Error(
      `Invalid authnContext.comparison "${String(authnContext.comparison)}": must be one of ${quote(
        AUTHN_CONTEXT_COMPARISONS,
      )}`,
    );
  }
};

// node-saml exposes the parsed (xml2js) assertion: child elements as arrays (the first one is taken), attributes within
// "$" and text within "_", e.g. { Assertion: { $: { ID: '...' }, AuthnStatement: [{ AuthnContext: [{ ... }] }] } }
const resolveAssertionNode = (profile: Profile, path: Array<string>): unknown => {
  return path.reduce<unknown>((node, name) => {
    const child: unknown = isObject(node) ? node[name] : undefined;

    return Array.isArray(child) ? child[0] : child;
  }, profile.getAssertion?.());
};

const resolveAuthnContextClassRef = (profile: Profile): string | undefined => {
  const classRef = resolveAssertionNode(profile, [
    'Assertion',
    'AuthnStatement',
    'AuthnContext',
    'AuthnContextClassRef',
  ]);

  return isObject(classRef) && isNonEmptyString(classRef._) ? classRef._ : undefined;
};

// the bearer assertion must be addressed to the assertion consumer service it got delivered to (web browser sso
// profile 4.1.4.5): node-saml does not verify the Recipient, so an assertion issued for another endpoint (of this or
// another service provider sharing the entity id) is rejected here
const assertRecipient = (profile: Profile, assertionConsumerServiceUrl: string): void => {
  const recipient = resolveAssertionNode(profile, [
    'Assertion',
    'Subject',
    'SubjectConfirmation',
    'SubjectConfirmationData',
    '$',
    'Recipient',
  ]);

  if (recipient !== assertionConsumerServiceUrl) {
    throw new InvalidSamlResponseError(
      `Recipient mismatch: expected "${assertionConsumerServiceUrl}", given "${String(recipient)}"`,
    );
  }
};

// with an exact comparison the identity provider must authenticate with one of the requested classes: an identity
// provider ignoring the request (e.g. a password login instead of the requested multi factor class) must not be
// trusted for a login it never performed. The other comparisons depend on an ordering only the identity provider knows
const assertAuthnContextClassRef = (identity: SamlIdentity, authnContext: AuthnContext | undefined): void => {
  if (authnContext === undefined || (authnContext.comparison ?? 'exact') !== 'exact') {
    return;
  }

  if (identity.authnContextClassRef === undefined || !authnContext.classRefs.includes(identity.authnContextClassRef)) {
    throw new InvalidSamlResponseError(
      `Authentication context mismatch: expected one of ${quote(authnContext.classRefs)}, given "${String(
        identity.authnContextClassRef,
      )}"`,
    );
  }
};

const resolveNotOnOrAfter = (profile: Profile, path: Array<string>): number | undefined => {
  const notOnOrAfter = resolveAssertionNode(profile, [...path, '$', 'NotOnOrAfter']);

  // node-saml already rejected an unparsable date
  return isNonEmptyString(notOnOrAfter) ? Date.parse(notOnOrAfter) : undefined;
};

// the id and the end of validity of the assertion: a bearer assertion must not be accepted twice (web browser sso
// profile 4.1.4.5), and its id must be remembered as long as the assertion could still be valid, so the later of the
// subject confirmation's and the conditions' NotOnOrAfter (the profile requires the former, node-saml neither)
const resolveAssertionValidity = (profile: Profile): { id: string; notOnOrAfter: number } => {
  const id = resolveAssertionNode(profile, ['Assertion', '$', 'ID']);

  const notOnOrAfters = [
    resolveNotOnOrAfter(profile, ['Assertion', 'Subject', 'SubjectConfirmation', 'SubjectConfirmationData']),
    resolveNotOnOrAfter(profile, ['Assertion', 'Conditions']),
  ].filter((notOnOrAfter) => notOnOrAfter !== undefined);

  if (!isNonEmptyString(id) || notOnOrAfters.length === 0) {
    throw new InvalidSamlResponseError('Missing ID or NotOnOrAfter within assertion');
  }

  return { id, notOnOrAfter: Math.max(...notOnOrAfters) };
};

// the root element of a saml protocol message (Response, LogoutRequest, LogoutResponse)
const parseProtocolRoot = (xml: string, localName: string, source: string): Element => {
  // oxlint-disable-next-line functional/no-let
  let root: Element | null;

  try {
    root = new DOMParser({ onError: onErrorStopParsing }).parseFromString(xml, 'text/xml').documentElement;
  } catch (error) {
    throw new InvalidSamlResponseError(`Cannot parse ${source}: invalid xml`, error);
  }

  if (root?.namespaceURI !== PROTOCOL_NAMESPACE || root.localName !== localName) {
    throw new InvalidSamlResponseError(`Missing ${localName} root element within ${source}`);
  }

  return root;
};

// a signed message must carry the url it was delivered to and the recipient must verify it (saml core 3.2.1, web
// browser sso profile 4.1.4.5): node-saml does not, so a message meant for another endpoint is rejected here
const assertDestination = (root: Element, destination: string, required: boolean): void => {
  const givenDestination = root.getAttribute('Destination');

  if (givenDestination === null && !required) {
    return;
  }

  if (givenDestination !== destination) {
    throw new InvalidSamlResponseError(
      `Destination mismatch: expected "${destination}", given "${String(givenDestination)}"`,
    );
  }
};

// a logout message (signed as a whole) must have been issued recently: node-saml only checks the optional NotOnOrAfter
// of a logout request, so without one a captured logout message could be replayed forever (to log a user out again
// and again, or to remove a session cookie via a replayed logout response)
const assertIssueInstant = (root: Element, clockTolerance: number): void => {
  const issueInstant = Date.parse(root.getAttribute('IssueInstant') ?? '');

  if (Number.isNaN(issueInstant)) {
    throw new InvalidSamlResponseError('Missing or invalid IssueInstant within logout message');
  }

  const now = Date.now();
  const toleranceMs = clockTolerance * 1000;

  if (issueInstant > now + toleranceMs || issueInstant + MAX_LOGOUT_MESSAGE_AGE * 1000 <= now - toleranceMs) {
    throw new InvalidSamlResponseError(
      `Logout message issued at "${new Date(issueInstant).toISOString()}" is not within the last ${MAX_LOGOUT_MESSAGE_AGE}s`,
    );
  }
};

// the raw query as received: the signature covers the url encoded SAMLRequest / SAMLResponse, RelayState and SigAlg
// parameters as sent by the identity provider, so node-saml verifies it against the original query string
const parseLogoutMessage = (
  query: string,
  type: LogoutMessageType,
  localName: 'LogoutRequest' | 'LogoutResponse',
  destination: string,
  clockTolerance: number,
): LogoutMessage => {
  const parameters = new URLSearchParams(query);

  const message = parameters.get(type);
  const sigAlg = parameters.get('SigAlg');
  const signature = parameters.get('Signature');

  if (!message) {
    throw new InvalidSamlResponseError(`Missing "${type}" parameter`);
  }

  // an unsigned logout message must not log anyone out (or in): node-saml only verifies a signature if there is one
  if (!sigAlg || !signature) {
    throw new InvalidSamlResponseError('Missing "SigAlg" or "Signature" parameter: the logout message must be signed');
  }

  if (!SIGNATURE_ALGORITHM_URIS.has(sigAlg)) {
    throw new InvalidSamlResponseError(`Unsupported signature algorithm "${sigAlg}"`);
  }

  // oxlint-disable-next-line functional/no-let
  let xml: string;

  try {
    xml = inflateRawSync(Buffer.from(message, 'base64'), { maxOutputLength: MAX_LOGOUT_MESSAGE_SIZE }).toString();
  } catch (error) {
    throw new InvalidSamlResponseError(`Cannot inflate "${type}" parameter`, error);
  }

  const root = parseProtocolRoot(xml, localName, `"${type}" parameter`);

  assertDestination(root, destination, true);
  assertIssueInstant(root, clockTolerance);

  return { container: { [type]: message, SigAlg: sigAlg, Signature: signature }, root };
};

const toSamlLogoutRequest = (profile: Profile): SamlLogoutRequest => {
  return {
    id: profile.ID as string,
    nameId: profile.nameID,
    ...(profile.nameIDFormat !== undefined ? { nameIdFormat: profile.nameIDFormat } : {}),
    ...(profile.sessionIndex !== undefined ? { sessionIndex: profile.sessionIndex } : {}),
  };
};

const toSamlIdentity = (profile: Profile): SamlIdentity => {
  const authnContextClassRef = resolveAuthnContextClassRef(profile);

  // node-saml types the name id format as required, but only sets it if the NameID carries a Format attribute
  return {
    nameId: profile.nameID,
    ...(profile.nameIDFormat !== undefined ? { nameIdFormat: profile.nameIDFormat } : {}),
    ...(profile.sessionIndex !== undefined ? { sessionIndex: profile.sessionIndex } : {}),
    ...(authnContextClassRef !== undefined ? { authnContextClassRef } : {}),
    issuer: profile.issuer,
    attributes: isObject(profile.attributes) ? profile.attributes : {},
  };
};

export const createSamlServiceProvider = (
  idpMetadataResolver: IdpMetadataResolver,
  options: SamlServiceProviderOptions,
): SamlServiceProvider => {
  // typescript enforces both, but a runtime check protects javascript consumers: without the entity id there is no
  // audience restriction, without the assertion consumer service url no destination check
  if (!isNonEmptyString(options.entityId)) {
    throw new Error('Invalid entityId: must be a non-empty string');
  }

  if (!isHttpUrl(options.assertionConsumerServiceUrl)) {
    throw new Error(
      `Invalid assertionConsumerServiceUrl "${String(options.assertionConsumerServiceUrl)}": must be an absolute http(s) url`,
    );
  }

  if (options.singleLogoutServiceUrl !== undefined) {
    if (!isHttpUrl(options.singleLogoutServiceUrl)) {
      throw new Error(
        `Invalid singleLogoutServiceUrl "${String(options.singleLogoutServiceUrl)}": must be an absolute http(s) url`,
      );
    }

    // a logout request or response sent via the http-redirect binding must be signed (saml profiles 4.4.4.1), and an
    // incoming one is only accepted if signed: without a key there is no single logout
    if (options.privateKey === undefined) {
      throw new Error('Invalid singleLogoutServiceUrl: requires privateKey (logout messages must be signed)');
    }
  }

  const {
    clockTolerance = 0,
    maxAssertionAge = 0,
    validateInResponseTo = 'never',
    assertionIdStore = createInMemorySamlAssertionIdStore(),
  } = options;

  assertNonNegative('clockTolerance', clockTolerance);
  assertNonNegative('maxAssertionAge', maxAssertionAge);

  if (!Object.hasOwn(VALIDATE_IN_RESPONSE_TO, validateInResponseTo)) {
    throw new Error(
      `Invalid validateInResponseTo "${String(validateInResponseTo)}": must be one of "never", "ifPresent", "always"`,
    );
  }

  if (options.authnContext !== undefined) {
    assertAuthnContext(options.authnContext);
  }

  if (options.signatureAlgorithm !== undefined && !SIGNATURE_ALGORITHMS.includes(options.signatureAlgorithm)) {
    throw new Error(
      `Unsupported signatureAlgorithm "${String(options.signatureAlgorithm)}", supported algorithms are ${quote(
        SIGNATURE_ALGORITHMS,
      )}`,
    );
  }

  const createSaml = (metadata: IdpMetadata, previousSaml: SAML | undefined): SAML => {
    return new SAML({
      idpCert: metadata.signingCertificates,
      idpIssuer: metadata.entityId,
      entryPoint: metadata.singleSignOnServiceUrl,
      issuer: options.entityId,
      callbackUrl: options.assertionConsumerServiceUrl,
      ...(metadata.singleLogoutServiceUrl !== undefined ? { logoutUrl: metadata.singleLogoutServiceUrl } : {}),
      audience: options.entityId,
      acceptedClockSkewMs: clockTolerance * 1000,
      maxAssertionAgeMs: maxAssertionAge * 1000,
      ...(options.identifierFormat !== undefined ? { identifierFormat: options.identifierFormat } : {}),
      ...(options.forceAuthn !== undefined ? { forceAuthn: options.forceAuthn } : {}),
      ...(options.wantAssertionsSigned !== undefined ? { wantAssertionsSigned: options.wantAssertionsSigned } : {}),
      ...(options.wantAuthnResponseSigned !== undefined
        ? { wantAuthnResponseSigned: options.wantAuthnResponseSigned }
        : {}),
      validateInResponseTo: VALIDATE_IN_RESPONSE_TO[validateInResponseTo],
      // node-saml would request "PasswordProtectedTransport" (exact) by default: an identity provider honouring it
      // could reject the request or force a password login where e.g. a mfa or kerberos login is configured, so
      // without an explicit authnContext the choice is left to the identity provider (no RequestedAuthnContext)
      ...(options.authnContext !== undefined
        ? { authnContext: options.authnContext.classRefs, racComparison: options.authnContext.comparison ?? 'exact' }
        : { disableRequestedAuthnContext: true }),
      ...(options.privateKey !== undefined
        ? {
            privateKey: options.privateKey,
            publicCert: options.certificate,
            signatureAlgorithm: options.signatureAlgorithm ?? 'sha256',
          }
        : {}),
      ...(options.decryptionKey !== undefined ? { decryptionPvk: options.decryptionKey } : {}),
      // rotated metadata replaces the saml instance: carry the request id cache over, so that a pending login can
      // still be validated (validateInResponseTo)
      ...(previousSaml ? { cacheProvider: previousSaml.cacheProvider } : {}),
    });
  };

  // oxlint-disable-next-line functional/no-let
  let cache: { metadata: IdpMetadata; saml: SAML } | undefined;

  const resolveSaml = async (): Promise<{ metadata: IdpMetadata; saml: SAML }> => {
    const metadata = await idpMetadataResolver();

    if (cache?.metadata !== metadata) {
      cache = { metadata, saml: createSaml(metadata, cache?.saml) };
    }

    return cache;
  };

  const resolveLoginUrl = async (relayState: string): Promise<string> => {
    const { saml } = await resolveSaml();

    return saml.getAuthorizeUrlAsync(relayState, undefined, {});
  };

  const verifySamlResponse = async (samlResponse: string): Promise<SamlIdentity> => {
    const { metadata, saml } = await resolveSaml();

    // oxlint-disable-next-line functional/no-let
    let result: Awaited<ReturnType<SAML['validatePostResponseAsync']>>;

    try {
      result = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });
    } catch (error) {
      // an encrypted assertion without a decryption key is a configuration problem, not an invalid saml response:
      // rethrown as an internal failure (node-saml verifies the response signature before it tries to decrypt, so with
      // wantAuthnResponseSigned the assertion is one of the trusted identity provider)
      if (error instanceof Error && error.message === MISSING_DECRYPTION_KEY_MESSAGE) {
        throw new Error('Cannot verify the saml response: encrypted assertion without decryptionKey', { cause: error });
      }

      // node-saml otherwise only throws about the given saml response here (malformed, wrong signature, expired,
      // wrong issuer / audience, non success status, ...), the idp metadata got resolved before
      throw new InvalidSamlResponseError(error instanceof Error ? error.message : String(error), error);
    }

    const { profile, loggedOut } = result;

    if (loggedOut || !profile) {
      throw new InvalidSamlResponseError('Logout response instead of an authn response');
    }

    const identity = toSamlIdentity(profile);

    // node-saml only verifies the signature against the trusted certificates, not the issuer of the assertion: an
    // identity provider signing for multiple issuers (e.g. tenants) with one key must not be able to cross them
    if (identity.issuer !== metadata.entityId) {
      throw new InvalidSamlResponseError(
        `Issuer mismatch: expected "${metadata.entityId}", given "${identity.issuer}"`,
      );
    }

    // the destination of the (verified) response: a signed response must carry it, an unsigned one
    // (wantAuthnResponseSigned: false) does not protect it anyway, so it is only checked if present
    assertDestination(
      parseProtocolRoot(profile.getSamlResponseXml?.() ?? '', 'Response', 'saml response'),
      options.assertionConsumerServiceUrl,
      options.wantAuthnResponseSigned !== false,
    );

    assertRecipient(profile, options.assertionConsumerServiceUrl);

    assertAuthnContextClassRef(identity, options.authnContext);

    const { id, notOnOrAfter } = resolveAssertionValidity(profile);

    // last, so that only an otherwise valid assertion consumes its id: the id is kept as long as the assertion would
    // still be accepted (its NotOnOrAfter plus the clock tolerance)
    if (!(await assertionIdStore.consume(id, notOnOrAfter + clockTolerance * 1000))) {
      throw new InvalidSamlResponseError(`Replayed assertion "${id}"`);
    }

    return identity;
  };

  const resolveLogoutUrl = async (identity: SamlIdentity, relayState: string): Promise<string | undefined> => {
    const { metadata, saml } = await resolveSaml();

    // without a single logout location on either side the logout response could not be delivered: local logout only
    if (options.singleLogoutServiceUrl === undefined || metadata.singleLogoutServiceUrl === undefined) {
      return undefined;
    }

    // node-saml types the name id format as required, but omits the Format attribute for an undefined one (the identity
    // provider sent none, so none goes back)
    const profile = {
      issuer: identity.issuer,
      nameID: identity.nameId,
      nameIDFormat: identity.nameIdFormat,
      sessionIndex: identity.sessionIndex,
    } as Profile;

    return saml.getLogoutUrlAsync(profile, relayState, {});
  };

  const resolveLogoutServiceUrl = (): string => {
    if (options.singleLogoutServiceUrl === undefined) {
      throw new Error('Single logout is not configured: missing singleLogoutServiceUrl');
    }

    return options.singleLogoutServiceUrl;
  };

  const verifyLogoutRequest = async (query: string): Promise<SamlLogoutRequest> => {
    const singleLogoutServiceUrl = resolveLogoutServiceUrl();

    const { metadata, saml } = await resolveSaml();

    const { container } = parseLogoutMessage(
      query,
      'SAMLRequest',
      'LogoutRequest',
      singleLogoutServiceUrl,
      clockTolerance,
    );

    // the logout response is sent to the single logout location of the metadata: without one there is nowhere to
    // answer, and an identity provider not advertising single logout should not request it
    if (metadata.singleLogoutServiceUrl === undefined) {
      throw new InvalidSamlResponseError(
        `Unexpected logout request: no single logout location within the idp metadata for entity id "${metadata.entityId}"`,
      );
    }

    // oxlint-disable-next-line functional/no-let
    let result: Awaited<ReturnType<SAML['validateRedirectAsync']>>;

    try {
      // node-saml verifies the query signature against the trusted certificates, the issuer and (if given) NotOnOrAfter
      result = await saml.validateRedirectAsync(container, query);
    } catch (error) {
      throw new InvalidSamlResponseError(error instanceof Error ? error.message : String(error), error);
    }

    return toSamlLogoutRequest(result.profile as Profile);
  };

  const resolveLogoutResponseUrl = async (
    logoutRequest: SamlLogoutRequest,
    relayState: string | undefined,
    success: boolean,
  ): Promise<string> => {
    const { saml } = await resolveSaml();

    // node-saml only needs the id of the logout request to answer (InResponseTo), the profile type wants more
    const profile = { ID: logoutRequest.id, issuer: '', nameID: '', nameIDFormat: '' };

    return saml.getLogoutResponseUrlAsync(profile, relayState ?? '', {}, success);
  };

  const verifyLogoutResponse = async (query: string): Promise<void> => {
    const singleLogoutServiceUrl = resolveLogoutServiceUrl();

    const { saml } = await resolveSaml();

    const { container, root } = parseLogoutMessage(
      query,
      'SAMLResponse',
      'LogoutResponse',
      singleLogoutServiceUrl,
      clockTolerance,
    );

    // node-saml only validates a given InResponseTo, never a missing one: with "always" an unsolicited logout
    // response is rejected here
    if (validateInResponseTo === 'always' && !root.getAttribute('InResponseTo')) {
      throw new InvalidSamlResponseError('Missing InResponseTo within logout response');
    }

    try {
      // node-saml verifies the status, the issuer, the query signature and (validateInResponseTo) the InResponseTo
      await saml.validateRedirectAsync(container, query);
    } catch (error) {
      throw new InvalidSamlResponseError(error instanceof Error ? error.message : String(error), error);
    }
  };

  return {
    resolveLoginUrl,
    verifySamlResponse,
    resolveLogoutUrl,
    verifyLogoutRequest,
    resolveLogoutResponseUrl,
    verifyLogoutResponse,
  };
};
