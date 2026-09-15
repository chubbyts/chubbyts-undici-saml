import { Buffer } from 'node:buffer';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import { createLogger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { InvalidSamlResponseError } from './error.js';
import type { SamlIdentity, SamlLogoutRequest, SamlServiceProvider } from './service-provider.js';
import type { SamlSession } from './session.js';

export type SamlAttributes = {
  saml: {
    identity: SamlIdentity;
  };
};

/**
 * The paths handled by the middleware: the assertion consumer service (saml responses posted by the identity
 * provider) and optionally the single logout service (logout requests and responses of the identity provider via the
 * http-redirect binding, and a `POST` to start a service provider initiated logout).
 */
export type SamlAuthenticationMiddlewarePaths = {
  assertionConsumerServicePath: string;
  singleLogoutServicePath?: string;
};

// only a same-origin absolute path is followed after login: anything else within the relay state (absolute urls,
// protocol-relative "//host", "/\host" which browsers treat alike, ...) would be an open redirect
const resolveRedirectTarget = (relayState: unknown): string => {
  // a same-origin absolute path only: no scheme / authority (open redirect) and no control characters or whitespace
  if (typeof relayState === 'string' && /^\/(?![/\\])[\x21-\x7E]*$/.test(relayState)) {
    return relayState;
  }

  return '/';
};

// a real saml response is a few dozen kilobytes at most (even with an encrypted assertion and many attributes):
// anything larger is not verified at all, since parsing and signature verification of an arbitrarily large, adversarial
// xml document would exhaust cpu and memory (the assertion consumer service is reachable without authentication). The
// same limit bounds the form body of the logout post (reachable without authentication as well)
export const MAX_SAML_RESPONSE_SIZE = 262_144;

const FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded';

// responses which set, clear or depend on a session cookie must not be stored by any (shared) cache
const NO_STORE_HEADERS = { 'cache-control': 'no-store' };

const createTextResponse = (status: number, statusText: string, body: string): Response => {
  return new Response(body, {
    status,
    statusText,
    headers: { ...NO_STORE_HEADERS, 'content-type': 'text/plain; charset=utf-8' },
  });
};

// the form body (http-post binding) read in a streaming way and bounded by size, since request.formData() would buffer
// a body of any size (chunked, or with a lying content length) before anything could be checked, and the server in
// front does not bound it either: undefined if the body exceeds the limit, an empty form if there is no (form) body
const readFormBody = async (request: ServerRequest, maxSize: number): Promise<URLSearchParams | undefined> => {
  // the content length (if given) is checked before anything is read
  if (Number(request.headers.get('content-length') ?? 0) > maxSize) {
    return undefined;
  }

  const mediaType = (request.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase();

  if (mediaType !== FORM_MEDIA_TYPE || !request.body) {
    return new URLSearchParams();
  }

  const reader = request.body.getReader();
  const chunks: Array<Uint8Array> = [];

  // oxlint-disable-next-line functional/no-let
  let size = 0;

  // oxlint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();

    if (done) {
      return new URLSearchParams(Buffer.concat(chunks).toString());
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

// the logout request names the principal and (optionally) the session to log out: only a matching session gets
// terminated, another session within the same browser is left alone and the identity provider gets a failure response
const matchesSession = (identity: SamlIdentity, logoutRequest: SamlLogoutRequest): boolean => {
  return (
    identity.nameId === logoutRequest.nameId &&
    (logoutRequest.sessionIndex === undefined || identity.sessionIndex === logoutRequest.sessionIndex)
  );
};

const createRedirectResponse = (location: string, cookie?: string): Response => {
  return new Response(undefined, {
    status: 303,
    statusText: 'See Other',
    headers: { ...NO_STORE_HEADERS, location, ...(cookie !== undefined ? { 'set-cookie': cookie } : {}) },
  });
};

export const createSamlAuthenticationMiddleware = (
  samlSession: SamlSession,
  samlServiceProvider: SamlServiceProvider,
  paths: string | SamlAuthenticationMiddlewarePaths,
  logger: Logger = createLogger(),
): Middleware => {
  const { assertionConsumerServicePath, singleLogoutServicePath } =
    typeof paths === 'string' ? { assertionConsumerServicePath: paths, singleLogoutServicePath: undefined } : paths;

  if (!assertionConsumerServicePath.startsWith('/')) {
    throw new Error(`Invalid assertionConsumerServicePath "${assertionConsumerServicePath}": must start with "/"`);
  }

  if (singleLogoutServicePath !== undefined && !singleLogoutServicePath.startsWith('/')) {
    throw new Error(`Invalid singleLogoutServicePath "${singleLogoutServicePath}": must start with "/"`);
  }

  if (singleLogoutServicePath === assertionConsumerServicePath) {
    throw new Error(
      `Invalid singleLogoutServicePath "${singleLogoutServicePath}": must differ from the assertionConsumerServicePath`,
    );
  }

  // an invalid saml message is answered with a 403, anything else (unreachable identity provider, ...) is rethrown
  const forbid = (request: ServerRequest, url: URL, name: string, error: unknown): Response => {
    if (!(error instanceof InvalidSamlResponseError)) {
      throw error;
    }

    logger.info(`Invalid ${name}`, {
      method: request.method,
      pathname: url.pathname,
      error: { name: error.name, message: error.message, cause: error.cause },
    });

    // do not reflect the verification error to the client: it may leak internal details (entity ids, ...)
    return createTextResponse(403, 'Forbidden', `The ${name} is invalid or expired`);
  };

  const consumeSamlResponse = async (request: ServerRequest, url: URL): Promise<Response> => {
    const form = await readFormBody(request, MAX_SAML_RESPONSE_SIZE);

    if (form === undefined) {
      return createTextResponse(413, 'Content Too Large', 'The saml response exceeds the maximum size');
    }

    const samlResponse = form.get('SAMLResponse');

    if (samlResponse === null || samlResponse === '') {
      return createTextResponse(400, 'Bad Request', 'Missing "SAMLResponse" parameter');
    }

    // oxlint-disable-next-line functional/no-let
    let identity: SamlIdentity;

    try {
      identity = await samlServiceProvider.verifySamlResponse(samlResponse);
    } catch (error) {
      return forbid(request, url, 'saml response', error);
    }

    return createRedirectResponse(
      resolveRedirectTarget(form.get('RelayState')),
      await samlSession.createCookie(identity),
    );
  };

  // identity provider initiated single logout: the identity provider sends a logout request (http-redirect binding),
  // the matching session gets removed and the browser is sent back with a logout response
  const consumeLogoutRequest = async (request: ServerRequest, url: URL): Promise<Response> => {
    // oxlint-disable-next-line functional/no-let
    let logoutRequest: SamlLogoutRequest;

    try {
      logoutRequest = await samlServiceProvider.verifyLogoutRequest(url.search.slice(1));
    } catch (error) {
      return forbid(request, url, 'saml logout request', error);
    }

    const identity = await samlSession.resolveIdentity(request);

    // without a session there is nothing left to log out (already logged out, expired): still a success
    const success = identity === undefined || matchesSession(identity, logoutRequest);

    // the relay state is the identity provider's own and goes back to it as is
    const location = await samlServiceProvider.resolveLogoutResponseUrl(
      logoutRequest,
      url.searchParams.get('RelayState') ?? undefined,
      success,
    );

    return createRedirectResponse(location, success ? samlSession.createRemovalCookie() : undefined);
  };

  // the identity provider's answer to a service provider initiated single logout: the session got removed when the
  // logout started, so the browser is only sent on to the relay state
  const consumeLogoutResponse = async (request: ServerRequest, url: URL): Promise<Response> => {
    try {
      await samlServiceProvider.verifyLogoutResponse(url.search.slice(1));
    } catch (error) {
      return forbid(request, url, 'saml logout response', error);
    }

    return createRedirectResponse(
      resolveRedirectTarget(url.searchParams.get('RelayState')),
      samlSession.createRemovalCookie(),
    );
  };

  // service provider initiated single logout: the session gets removed right away (the local logout must not depend on
  // the identity provider) and the browser is sent to the identity provider with a logout request, or straight to the
  // relay state if single logout is not available. A POST (not a GET) on purpose: with the SameSite=Lax cookie a
  // cross-site request carries no session, so another site cannot log the user out
  const initiateLogout = async (request: ServerRequest): Promise<Response> => {
    const form = await readFormBody(request, MAX_SAML_RESPONSE_SIZE);

    if (form === undefined) {
      return createTextResponse(413, 'Content Too Large', 'The request body exceeds the maximum size');
    }

    const relayState = resolveRedirectTarget(form.get('RelayState'));

    const identity = await samlSession.resolveIdentity(request);

    const location = identity ? await samlServiceProvider.resolveLogoutUrl(identity, relayState) : undefined;

    return createRedirectResponse(location ?? relayState, samlSession.createRemovalCookie());
  };

  return async (request: ServerRequest, handler: Handler): Promise<Response> => {
    const url = new URL(request.url);

    if (url.pathname === assertionConsumerServicePath && request.method === 'POST') {
      return consumeSamlResponse(request, url);
    }

    if (url.pathname === singleLogoutServicePath) {
      if (request.method === 'GET' && url.searchParams.has('SAMLRequest')) {
        return consumeLogoutRequest(request, url);
      }

      if (request.method === 'GET' && url.searchParams.has('SAMLResponse')) {
        return consumeLogoutResponse(request, url);
      }

      if (request.method === 'POST') {
        return initiateLogout(request);
      }
    }

    const identity = await samlSession.resolveIdentity(request);

    if (identity) {
      return handler(new ServerRequest(request, { attributes: { ...request.attributes, saml: { identity } } }));
    }

    // only a navigation request can be sent to the identity provider: redirecting anything else (an expired session
    // within a POST, a fetch from a spa, ...) would silently drop the request body or answer it with a html login page
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response(undefined, { status: 401, statusText: 'Unauthorized', headers: NO_STORE_HEADERS });
    }

    return new Response(undefined, {
      status: 302,
      statusText: 'Found',
      headers: {
        ...NO_STORE_HEADERS,
        location: await samlServiceProvider.resolveLoginUrl(url.pathname + url.search),
      },
    });
  };
};
