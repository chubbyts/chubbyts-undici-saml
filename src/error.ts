/**
 * Thrown by a saml response, logout request or logout response verifier if the given saml message itself is invalid
 * (malformed, unsigned, wrong signature, expired, wrong issuer / audience / destination, non success status, ...).
 * Any other error thrown by a verifier is treated as an internal failure (unreachable idp metadata endpoint, ...) and
 * gets rethrown by the middleware.
 */
export class InvalidSamlResponseError extends Error {
  public constructor(message: string, cause?: unknown) {
    super(message, { cause });
    // oxlint-disable-next-line functional/immutable-data
    this.name = 'InvalidSamlResponseError';
  }
}

/**
 * Thrown by the idp metadata resolver if the metadata cannot be fetched from the identity provider (non 2xx status,
 * timeout, invalid xml) or is invalid (entity id mismatch, missing signing certificate, missing / insecure single
 * sign-on location, ...). Treated as an internal failure by the middleware.
 */
export class IdpMetadataError extends Error {
  public constructor(message: string, cause?: unknown) {
    super(message, { cause });
    // oxlint-disable-next-line functional/immutable-data
    this.name = 'IdpMetadataError';
  }
}
