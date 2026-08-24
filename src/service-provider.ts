import type { Profile } from '@node-saml/node-saml';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
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
  nameIdFormat: string;
  sessionIndex?: string;
  authnContextClassRef?: string;
  issuer: string;
  attributes: Record<string, unknown>;
};

export type LoginUrlResolver = (relayState: string) => Promise<string>;

export type SamlResponseVerifier = (samlResponse: string) => Promise<SamlIdentity>;

export type SamlServiceProvider = {
  resolveLoginUrl: LoginUrlResolver;
  verifySamlResponse: SamlResponseVerifier;
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
};

const VALIDATE_IN_RESPONSE_TO: Record<'never' | 'ifPresent' | 'always', ValidateInResponseTo> = {
  never: ValidateInResponseTo.never,
  ifPresent: ValidateInResponseTo.ifPresent,
  always: ValidateInResponseTo.always,
};

const AUTHN_CONTEXT_COMPARISONS: ReadonlyArray<string> = ['exact', 'minimum', 'maximum', 'better'];

// sha1 is supported by node-saml, but deliberately not offered: it is broken for signatures
const SIGNATURE_ALGORITHMS: ReadonlyArray<string> = ['sha256', 'sha512'];

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

// node-saml does not expose the authn context within the profile, but the parsed (xml2js) assertion:
// { Assertion: { AuthnStatement: [{ AuthnContext: [{ AuthnContextClassRef: [{ _: '...' }] }] }] } }
const resolveAuthnContextClassRef = (profile: Profile): string | undefined => {
  const path = ['Assertion', 'AuthnStatement', 'AuthnContext', 'AuthnContextClassRef'];

  const classRef = path.reduce<unknown>((node, name) => {
    const child: unknown = isObject(node) ? node[name] : undefined;

    return Array.isArray(child) ? child[0] : child;
  }, profile.getAssertion?.());

  return isObject(classRef) && isNonEmptyString(classRef._) ? classRef._ : undefined;
};

const toSamlIdentity = (profile: Profile): SamlIdentity => {
  const authnContextClassRef = resolveAuthnContextClassRef(profile);

  return {
    nameId: profile.nameID,
    nameIdFormat: profile.nameIDFormat,
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

  const { clockTolerance = 0, maxAssertionAge = 0, validateInResponseTo = 'never' } = options;

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
      // node-saml only throws about the given saml response here (malformed, wrong signature, expired, wrong
      // issuer / audience, non success status, ...), the idp metadata got resolved before
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

    return identity;
  };

  return { resolveLoginUrl, verifySamlResponse };
};
