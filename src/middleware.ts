import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import { createLogger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { InvalidSamlResponseError } from './error.js';
import type { SamlIdentity, SamlServiceProvider } from './service-provider.js';
import type { SamlSession } from './session.js';

export type SamlAttributes = {
  saml: {
    identity: SamlIdentity;
  };
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
// xml document would exhaust cpu and memory (the assertion consumer service is reachable without authentication)
export const MAX_SAML_RESPONSE_SIZE = 262_144;

// responses which set, clear or depend on a session cookie must not be stored by any (shared) cache
const NO_STORE_HEADERS = { 'cache-control': 'no-store' };

const createTextResponse = (status: number, statusText: string, body: string): Response => {
  return new Response(body, {
    status,
    statusText,
    headers: { ...NO_STORE_HEADERS, 'content-type': 'text/plain; charset=utf-8' },
  });
};

// the content length (if given) is checked before the body is read; a chunked body is bounded by the server in front
const exceedsMaxSize = (request: ServerRequest): boolean => {
  const contentLength = Number(request.headers.get('content-length') ?? 0);

  return !Number.isNaN(contentLength) && contentLength > MAX_SAML_RESPONSE_SIZE;
};

export const createSamlAuthenticationMiddleware = (
  samlSession: SamlSession,
  samlServiceProvider: SamlServiceProvider,
  assertionConsumerServicePath: string,
  logger: Logger = createLogger(),
): Middleware => {
  if (!assertionConsumerServicePath.startsWith('/')) {
    throw new Error(`Invalid assertionConsumerServicePath "${assertionConsumerServicePath}": must start with "/"`);
  }

  const consumeSamlResponse = async (request: ServerRequest, url: URL): Promise<Response> => {
    if (exceedsMaxSize(request)) {
      return createTextResponse(413, 'Content Too Large', 'The saml response exceeds the maximum size');
    }

    const formData = await request.formData().catch(() => undefined);

    const samlResponse = formData?.get('SAMLResponse');

    if (typeof samlResponse !== 'string' || samlResponse === '') {
      return createTextResponse(400, 'Bad Request', 'Missing "SAMLResponse" parameter');
    }

    if (samlResponse.length > MAX_SAML_RESPONSE_SIZE) {
      return createTextResponse(413, 'Content Too Large', 'The saml response exceeds the maximum size');
    }

    // oxlint-disable-next-line functional/no-let
    let identity: SamlIdentity;

    try {
      identity = await samlServiceProvider.verifySamlResponse(samlResponse);
    } catch (error) {
      if (!(error instanceof InvalidSamlResponseError)) {
        throw error;
      }

      logger.info('Invalid saml response', {
        method: request.method,
        pathname: url.pathname,
        error: { name: error.name, message: error.message, cause: error.cause },
      });

      // do not reflect the verification error to the client: it may leak internal details (entity ids, ...)
      return createTextResponse(403, 'Forbidden', 'The saml response is invalid or expired');
    }

    return new Response(undefined, {
      status: 303,
      statusText: 'See Other',
      headers: {
        ...NO_STORE_HEADERS,
        location: resolveRedirectTarget(formData?.get('RelayState')),
        'set-cookie': await samlSession.createCookie(identity),
      },
    });
  };

  return async (request: ServerRequest, handler: Handler): Promise<Response> => {
    const url = new URL(request.url);

    if (url.pathname === assertionConsumerServicePath && request.method === 'POST') {
      return consumeSamlResponse(request, url);
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
