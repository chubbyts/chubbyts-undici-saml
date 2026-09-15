import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom';
import type { Document, Element, Node } from '@xmldom/xmldom';
import { IdpMetadataError } from './error.js';
import { assertNonNegative, isHttpUrl } from './util.js';

export type IdpMetadata = {
  entityId: string;
  singleSignOnServiceUrl: string;
  singleLogoutServiceUrl?: string;
  signingCertificates: Array<string>;
};

export type IdpMetadataResolver = () => Promise<IdpMetadata>;

export type IdpMetadataResolverOptions = {
  entityId?: string;
  fetch?: typeof globalThis.fetch;
  maxAge?: number;
  timeout?: number;
  cooldown?: number;
  maxSize?: number;
};

const METADATA_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:metadata';
const SIGNATURE_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#';
const HTTP_REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

const isHttpsUrl = (value: string): boolean => new URL(value).protocol === 'https:';

const isTimeoutError = (error: unknown): boolean => {
  return error instanceof Error && error.name === 'TimeoutError';
};

// a string as is, anything else by its type (for error messages)
const describe = (value: unknown): string => {
  if (typeof value === 'string') {
    return value;
  }

  return value === null ? 'null' : typeof value;
};

// the timeout bounds a slow response, not a huge one: stop reading as soon as the body exceeds the limit
const readBody = async (response: Response, maxSize: number): Promise<string | undefined> => {
  if (!response.body) {
    return '';
  }

  const reader = response.body.getReader();
  const chunks: Array<Uint8Array> = [];

  // oxlint-disable-next-line functional/no-let
  let size = 0;

  // oxlint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();

    if (done) {
      return new TextDecoder().decode(Buffer.concat(chunks));
    }

    size += value.byteLength;

    if (size > maxSize) {
      await reader.cancel();

      return undefined;
    }

    // oxlint-disable-next-line functional/immutable-data
    chunks.push(value);
  }
};

const isElement = (node: Node): node is Element => node.nodeType === 1;

const childElements = (parent: Element, namespace: string, localName: string): Array<Element> => {
  return Array.from(parent.childNodes)
    .filter(isElement)
    .filter((element) => element.namespaceURI === namespace && element.localName === localName);
};

const parseXml = (metadataUrl: string, xml: string): Document => {
  // warnings are tolerated, any error stops parsing (the default would only stop at fatal errors)
  const parser = new DOMParser({ onError: onErrorStopParsing });

  try {
    return parser.parseFromString(xml, 'text/xml');
  } catch (error) {
    throw new IdpMetadataError(`Cannot fetch idp metadata from "${metadataUrl}": invalid xml`, error);
  }
};

// the http-redirect endpoint element (SingleSignOnService, SingleLogoutService) of the idp sso descriptor, if any
const resolveHttpRedirectService = (idpSsoDescriptor: Element, localName: string): Element | undefined => {
  return childElements(idpSsoDescriptor, METADATA_NAMESPACE, localName).find(
    (service) => service.getAttribute('Binding') === HTTP_REDIRECT_BINDING,
  );
};

const resolveSigningCertificates = (idpSsoDescriptor: Element): Array<string> => {
  return childElements(idpSsoDescriptor, METADATA_NAMESPACE, 'KeyDescriptor')
    .filter((keyDescriptor) => ['signing', null, ''].includes(keyDescriptor.getAttribute('use')))
    .flatMap((keyDescriptor) =>
      Array.from(keyDescriptor.getElementsByTagNameNS(SIGNATURE_NAMESPACE, 'X509Certificate')),
    )
    .map((certificateElement) => (certificateElement.textContent ?? '').replaceAll(/\s+/g, ''))
    .filter((certificate) => certificate !== '');
};

export const createIdpMetadataResolver = (
  metadataUrl: string,
  options: IdpMetadataResolverOptions = {},
): IdpMetadataResolver => {
  const { fetch = globalThis.fetch, maxAge = 3600, timeout = 5, cooldown = 30, maxSize = 1_048_576 } = options;

  if (!isHttpUrl(metadataUrl)) {
    throw new Error(`Invalid metadataUrl "${metadataUrl}": must be an absolute http(s) url`);
  }

  assertNonNegative('maxAge', maxAge);
  assertNonNegative('timeout', timeout);
  assertNonNegative('cooldown', cooldown);

  if (Number.isNaN(maxSize) || maxSize < 0) {
    throw new Error(`Invalid maxSize ${String(maxSize)}: must be a non-negative number of bytes`);
  }

  // a https metadata url must not downgrade a redirect to the identity provider to plain http (credentials would be
  // sent over an unprotected connection)
  const assertSecureLocation = (name: string, location: string): void => {
    if (isHttpsUrl(metadataUrl) && !isHttpsUrl(location)) {
      throw new IdpMetadataError(`Insecure ${name} location "${location}" for https metadata url "${metadataUrl}"`);
    }
  };

  const parseMetadata = (xml: string): IdpMetadata => {
    const root = parseXml(metadataUrl, xml).documentElement as Element | null;

    // an EntitiesDescriptor (federation aggregate) is out of scope on purpose: point the resolver at the metadata of
    // the one identity provider to trust
    if (!root || root.namespaceURI !== METADATA_NAMESPACE || root.localName !== 'EntityDescriptor') {
      throw new IdpMetadataError(`Missing EntityDescriptor root element within idp metadata from "${metadataUrl}"`);
    }

    const entityId = root.getAttribute('entityID');

    if (!entityId) {
      throw new IdpMetadataError(`Missing entityID within idp metadata from "${metadataUrl}"`);
    }

    if (options.entityId !== undefined && entityId !== options.entityId) {
      throw new IdpMetadataError(`Entity id mismatch: expected "${options.entityId}", given "${entityId}"`);
    }

    const idpSsoDescriptor = childElements(root, METADATA_NAMESPACE, 'IDPSSODescriptor')[0];

    if (!idpSsoDescriptor) {
      throw new IdpMetadataError(`Missing IDPSSODescriptor within idp metadata for entity id "${entityId}"`);
    }

    // whoever controls these certificates controls which saml responses are accepted: without any there is nothing to
    // verify against, so fail here with a clear message instead of on the first saml response
    const signingCertificates = resolveSigningCertificates(idpSsoDescriptor);

    if (signingCertificates.length === 0) {
      throw new IdpMetadataError(`Missing signing certificate within idp metadata for entity id "${entityId}"`);
    }

    const singleSignOnServiceUrl = resolveHttpRedirectService(idpSsoDescriptor, 'SingleSignOnService')?.getAttribute(
      'Location',
    );

    if (!isHttpUrl(singleSignOnServiceUrl)) {
      throw new IdpMetadataError(
        `Missing or invalid http-redirect single sign-on location "${describe(
          singleSignOnServiceUrl,
        )}" for entity id "${entityId}"`,
      );
    }

    assertSecureLocation('single sign-on', singleSignOnServiceUrl);

    // single logout is optional: without a http-redirect single logout location a logout only ends the local session
    const singleLogoutService = resolveHttpRedirectService(idpSsoDescriptor, 'SingleLogoutService');

    if (!singleLogoutService) {
      return { entityId, singleSignOnServiceUrl, signingCertificates };
    }

    const singleLogoutServiceUrl = singleLogoutService.getAttribute('Location');

    if (!isHttpUrl(singleLogoutServiceUrl)) {
      throw new IdpMetadataError(
        `Invalid http-redirect single logout location "${describe(singleLogoutServiceUrl)}" for entity id "${entityId}"`,
      );
    }

    assertSecureLocation('single logout', singleLogoutServiceUrl);

    return { entityId, singleSignOnServiceUrl, singleLogoutServiceUrl, signingCertificates };
  };

  // oxlint-disable-next-line functional/no-let
  let cache: { metadata: IdpMetadata; validUntil: number } | undefined;

  // oxlint-disable-next-line functional/no-let
  let failure: { error: unknown; retryAfter: number } | undefined;

  // oxlint-disable-next-line functional/no-let
  let pending: Promise<IdpMetadata> | undefined;

  const fetchMetadata = async (): Promise<IdpMetadata> => {
    // the metadata endpoint should not redirect, and following redirects would silently bypass the https checks
    // (https -> http redirect)
    const response = await fetch(metadataUrl, {
      signal: AbortSignal.timeout(timeout * 1000),
      redirect: 'manual',
    }).catch((error: unknown) => {
      if (isTimeoutError(error)) {
        throw new IdpMetadataError(`Cannot fetch idp metadata from "${metadataUrl}": timeout after ${timeout}s`, error);
      }

      throw error;
    });

    if (!response.ok) {
      throw new IdpMetadataError(`Cannot fetch idp metadata from "${metadataUrl}": status ${response.status}`);
    }

    const xml = await readBody(response, maxSize);

    if (xml === undefined) {
      throw new IdpMetadataError(`Cannot fetch idp metadata from "${metadataUrl}": exceeds ${maxSize} bytes`);
    }

    return parseMetadata(xml);
  };

  // an identity provider outage should not take the service provider down: keep serving the last known metadata and
  // only fail if there never was one
  const resolveStaleMetadata = (error: unknown): IdpMetadata => {
    if (cache) {
      return cache.metadata;
    }

    throw error;
  };

  const resolveMetadata = async (): Promise<IdpMetadata> => {
    try {
      const metadata = await fetchMetadata();

      cache = { metadata, validUntil: Date.now() + maxAge * 1000 };
      failure = undefined;

      return metadata;
    } catch (error) {
      // fail fast during an outage instead of hitting the identity provider with every request
      failure = { error, retryAfter: Date.now() + cooldown * 1000 };

      return resolveStaleMetadata(error);
    } finally {
      pending = undefined;
    }
  };

  return async (): Promise<IdpMetadata> => {
    if (cache && cache.validUntil > Date.now()) {
      return cache.metadata;
    }

    if (failure && failure.retryAfter > Date.now()) {
      return resolveStaleMetadata(failure.error);
    }

    // concurrent cache misses share one in-flight request
    pending ??= resolveMetadata();

    // stale-while-revalidate: an expired cache is served right away while the refresh runs in the background, so that
    // no request has to wait for the identity provider (a rotation takes effect with the next request)
    return cache ? cache.metadata : pending;
  };
};
