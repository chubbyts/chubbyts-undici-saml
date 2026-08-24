import { createHash } from 'node:crypto';
import { EncryptJWT, jwtDecrypt } from 'jose';
import type { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { SamlIdentity } from './service-provider.js';
import { assertNonNegative, isObject } from './util.js';

export type SamlSession = {
  resolveIdentity: (request: ServerRequest) => Promise<SamlIdentity | undefined>;
  createCookie: (identity: SamlIdentity) => Promise<string>;
  createRemovalCookie: () => string;
};

export type SamlSessionOptions = {
  secret: string;
  maxAge?: number;
  cookieName?: string;
  path?: string;
  secure?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
};

const SAME_SITE_VALUES: ReadonlyArray<string> = ['Lax', 'Strict', 'None'];

// cookie-name is a rfc 6265 token: anything else could break out of the set-cookie header
const COOKIE_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

// path-value is a rfc 6265 path-value: any us-ascii char except controls, whitespace and ";"
const COOKIE_PATH_PATTERN = /^\/[\x21-\x3A\x3C-\x7E]*$/;

const resolveCookieValue = (request: ServerRequest, cookieName: string): string | undefined => {
  const prefix = `${cookieName}=`;

  return (request.headers.get('cookie') ?? '')
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(prefix))
    ?.slice(prefix.length);
};

/**
 * A stateless session: the verified identity is stored within an encrypted (and therefore also tamper-proof) jwt
 * cookie instead of a server side session storage. Trade-off: a session cannot be revoked before its `maxAge`, it
 * ends by cookie removal (logout) or expiration only.
 */
export const createSamlSession = (options: SamlSessionOptions): SamlSession => {
  const { secret, maxAge = 3600, cookieName = 'saml-session', path = '/', secure = true, sameSite = 'Lax' } = options;

  // the secret is the only thing between a client and a self-issued session: enforce a minimum length instead of
  // silently accepting a weak one
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error('Invalid secret: must be a string with at least 32 characters');
  }

  assertNonNegative('maxAge', maxAge);

  if (!COOKIE_NAME_PATTERN.test(cookieName)) {
    throw new Error(`Invalid cookieName "${cookieName}": must be a rfc 6265 token`);
  }

  if (!COOKIE_PATH_PATTERN.test(path)) {
    throw new Error(`Invalid path "${path}": must start with "/" and be a rfc 6265 path-value`);
  }

  if (!SAME_SITE_VALUES.includes(sameSite)) {
    throw new Error(`Invalid sameSite "${String(sameSite)}": must be one of "Lax", "Strict", "None"`);
  }

  // browsers reject SameSite=None cookies without the Secure attribute
  if (sameSite === 'None' && !secure) {
    throw new Error('Invalid sameSite "None": requires secure');
  }

  // dir / A256GCM needs a 256 bit key: derive it from the secret instead of restricting the secret to 32 bytes
  const key = createHash('sha256').update(secret).digest();

  const attributes = `; Path=${path}; HttpOnly; SameSite=${sameSite}${secure ? '; Secure' : ''}`;

  const resolveIdentity = async (request: ServerRequest): Promise<SamlIdentity | undefined> => {
    const cookieValue = resolveCookieValue(request, cookieName);

    if (!cookieValue) {
      return undefined;
    }

    // an invalid session cookie (tampered, expired, encrypted with a rotated secret) is not an error: the request is
    // simply not authenticated (anyone can send any cookie)
    try {
      const { payload } = await jwtDecrypt(cookieValue, key);

      return isObject(payload.identity) ? (payload.identity as SamlIdentity) : undefined;
    } catch {
      return undefined;
    }
  };

  const createCookie = async (identity: SamlIdentity): Promise<string> => {
    const issuedAt = Math.floor(Date.now() / 1000);

    const jwt = await new EncryptJWT({ identity })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + maxAge)
      .encrypt(key);

    return `${cookieName}=${jwt}${attributes}; Max-Age=${maxAge}`;
  };

  const createRemovalCookie = (): string => {
    return `${cookieName}=${attributes}; Max-Age=0`;
  };

  return { resolveIdentity, createCookie, createRemovalCookie };
};
