import { expect, test } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { useObjectMock } from '@chubbyts/chubbyts-function-mock/dist/object-mock';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Handler } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { InvalidSamlResponseError } from '../../src/error';
import type { SamlIdentity, SamlLogoutRequest, SamlServiceProvider } from '../../src/service-provider';
import type { SamlSession } from '../../src/session';
import type { SamlAuthenticationMiddlewarePaths } from '../../src/middleware';
import { MAX_SAML_RESPONSE_SIZE, createSamlAuthenticationMiddleware } from '../../src/middleware';

const paths: SamlAuthenticationMiddlewarePaths = {
  assertionConsumerServicePath: '/saml/acs',
  singleLogoutServicePath: '/saml/slo',
};

const identity: SamlIdentity = {
  nameId: 'user@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  sessionIndex: '_session-1',
  issuer: 'https://idp.example.com',
  attributes: {},
};

const logoutRequest: SamlLogoutRequest = {
  id: '_logout-request-1',
  nameId: 'user@example.com',
  sessionIndex: '_session-1',
};

const removalCookie = 'saml-session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0';

// a signed logout request / response query as an identity provider sends it (the middleware passes it through as is)
const logoutRequestQuery = 'SAMLRequest=some-logout-request&RelayState=idp-relay-state&SigAlg=alg&Signature=sig';
const logoutResponseQuery =
  'SAMLResponse=some-logout-response&RelayState=%2Fresource%3Fkey%3Dvalue&SigAlg=alg&Signature=sig';

const expectRedirect = (response: Response, location: string, cookie: string | undefined): void => {
  expect(response.status).toBe(303);
  expect(response.statusText).toBe('See Other');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'cache-control': 'no-store',
    location,
    ...(cookie !== undefined ? { 'set-cookie': cookie } : {}),
  });
};

test.each<{ name: string; paths: SamlAuthenticationMiddlewarePaths; message: string }>([
  {
    name: 'without leading slash',
    paths: { ...paths, singleLogoutServicePath: 'saml/slo' },
    message: 'Invalid singleLogoutServicePath "saml/slo": must start with "/"',
  },
  {
    name: 'same as assertionConsumerServicePath',
    paths: { ...paths, singleLogoutServicePath: '/saml/acs' },
    message: 'Invalid singleLogoutServicePath "/saml/acs": must differ from the assertionConsumerServicePath',
  },
])('with invalid singleLogoutServicePath: $name', ({ paths: invalidPaths, message }) => {
  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  expect(() => createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, invalidPaths)).toThrow(
    new Error(message),
  );

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
});

test('with logout request and matching session', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutRequestQuery}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifyLogoutRequest', parameters: [logoutRequestQuery], return: Promise.resolve(logoutRequest) },
    {
      name: 'resolveLogoutResponseUrl',
      parameters: [logoutRequest, 'idp-relay-state', true],
      return: Promise.resolve('https://idp.example.com/slo?SAMLResponse=some-logout-response'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, 'https://idp.example.com/slo?SAMLResponse=some-logout-response', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout request without session index and without relay state, with session', async () => {
  const serverRequest = new ServerRequest(
    'https://sp.example.com/saml/slo?SAMLRequest=some-logout-request&SigAlg=alg&Signature=sig',
  );

  const { sessionIndex: _, ...logoutRequestWithoutSessionIndex } = logoutRequest;

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'verifyLogoutRequest',
      parameters: ['SAMLRequest=some-logout-request&SigAlg=alg&Signature=sig'],
      return: Promise.resolve(logoutRequestWithoutSessionIndex),
    },
    {
      name: 'resolveLogoutResponseUrl',
      parameters: [logoutRequestWithoutSessionIndex, undefined, true],
      return: Promise.resolve('https://idp.example.com/slo?SAMLResponse=some-logout-response'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, 'https://idp.example.com/slo?SAMLResponse=some-logout-response', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout request without session', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutRequestQuery}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(undefined) },
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifyLogoutRequest', parameters: [logoutRequestQuery], return: Promise.resolve(logoutRequest) },
    {
      name: 'resolveLogoutResponseUrl',
      parameters: [logoutRequest, 'idp-relay-state', true],
      return: Promise.resolve('https://idp.example.com/slo?SAMLResponse=some-logout-response'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, 'https://idp.example.com/slo?SAMLResponse=some-logout-response', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test.each<{ name: string; identity: SamlIdentity }>([
  { name: 'name id', identity: { ...identity, nameId: 'other@example.com' } },
  { name: 'session index', identity: { ...identity, sessionIndex: '_session-2' } },
  { name: 'missing session index', identity: { ...identity, sessionIndex: undefined } },
])('with logout request and mismatching session: $name', async ({ identity: otherIdentity }) => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutRequestQuery}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(otherIdentity) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifyLogoutRequest', parameters: [logoutRequestQuery], return: Promise.resolve(logoutRequest) },
    {
      name: 'resolveLogoutResponseUrl',
      parameters: [logoutRequest, 'idp-relay-state', false],
      return: Promise.resolve('https://idp.example.com/slo?SAMLResponse=some-logout-response'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  // the session of another principal is kept: no removal cookie
  expectRedirect(response, 'https://idp.example.com/slo?SAMLResponse=some-logout-response', undefined);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with invalid logout request', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutRequestQuery}`);

  const cause = new Error('Invalid query signature');

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'verifyLogoutRequest',
      parameters: [logoutRequestQuery],
      error: new InvalidSamlResponseError('Invalid query signature', cause),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const [logger, loggerMocks] = useObjectMock<Logger>([
    {
      name: 'info',
      parameters: [
        'Invalid saml logout request',
        {
          method: 'GET',
          pathname: '/saml/slo',
          error: { name: 'InvalidSamlResponseError', message: 'Invalid query signature', cause },
        },
      ],
    },
  ]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths, logger);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(403);
  expect(response.statusText).toBe('Forbidden');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  });
  expect(await response.text()).toBe('The saml logout request is invalid or expired');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});

test('with failing logout request verifier', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutRequestQuery}`);

  const error = new Error('Cannot fetch idp metadata');

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifyLogoutRequest', parameters: [logoutRequestQuery], error },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  await expect(middleware(serverRequest, handler)).rejects.toBe(error);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout response', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutResponseQuery}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifyLogoutResponse', parameters: [logoutResponseQuery], return: Promise.resolve() },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, '/resource?key=value', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout response with open redirect relay state', async () => {
  const query = 'SAMLResponse=some-logout-response&RelayState=https%3A%2F%2Fevil.example.com&SigAlg=alg&Signature=sig';

  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${query}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifyLogoutResponse', parameters: [query], return: Promise.resolve() },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, '/', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with invalid logout response', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutResponseQuery}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'verifyLogoutResponse',
      parameters: [logoutResponseQuery],
      error: new InvalidSamlResponseError('Bad status code'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const [logger, loggerMocks] = useObjectMock<Logger>([
    {
      name: 'info',
      parameters: [
        'Invalid saml logout response',
        {
          method: 'GET',
          pathname: '/saml/slo',
          error: { name: 'InvalidSamlResponseError', message: 'Bad status code', cause: undefined },
        },
      ],
    },
  ]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths, logger);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(403);
  expect(await response.text()).toBe('The saml logout response is invalid or expired');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});

test('with logout with session', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/slo', {
    method: 'POST',
    body: new URLSearchParams({ RelayState: '/goodbye' }),
  });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'resolveLogoutUrl',
      parameters: [identity, '/goodbye'],
      return: Promise.resolve('https://idp.example.com/slo?SAMLRequest=some-logout-request'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, 'https://idp.example.com/slo?SAMLRequest=some-logout-request', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout with session and without single logout', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/slo', {
    method: 'POST',
    body: new URLSearchParams({ RelayState: '/goodbye' }),
  });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'resolveLogoutUrl', parameters: [identity, '/goodbye'], return: Promise.resolve(undefined) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, '/goodbye', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout with too large body', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/slo', {
    method: 'POST',
    body: new URLSearchParams({ RelayState: `/${'x'.repeat(MAX_SAML_RESPONSE_SIZE)}` }),
  });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);
  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(413);
  expect(response.statusText).toBe('Content Too Large');
  expect(await response.text()).toBe('The request body exceeds the maximum size');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with logout without session and without body', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/slo', { method: 'POST' });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(undefined) },
    { name: 'createRemovalCookie', parameters: [], return: removalCookie },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  const response = await middleware(serverRequest, handler);

  expectRedirect(response, '/', removalCookie);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test.each<{ name: string; url: string; method: string }>([
  { name: 'get without saml message', url: 'https://sp.example.com/saml/slo', method: 'GET' },
  {
    name: 'get with saml message within the fragment only',
    url: 'https://sp.example.com/saml/slo#SAMLRequest=x',
    method: 'GET',
  },
  { name: 'put with logout request', url: `https://sp.example.com/saml/slo?${logoutRequestQuery}`, method: 'PUT' },
  { name: 'put with logout response', url: `https://sp.example.com/saml/slo?${logoutResponseQuery}`, method: 'PUT' },
])('with single logout service path and unrelated request: $name', async ({ url, method }) => {
  const serverRequest = new ServerRequest(url, { method });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  const handlerResponse = new Response('OK');

  const [handler, handlerMocks] = useFunctionMock<Handler>([
    {
      callback: async (handledServerRequest: ServerRequest): Promise<Response> => {
        expect(handledServerRequest.attributes).toEqual({ saml: { identity } });

        return handlerResponse;
      },
    },
  ]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, paths);

  // handled like any other request: with a session it reaches the handler
  expect(await middleware(serverRequest, handler)).toBe(handlerResponse);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('without single logout service path', async () => {
  const serverRequest = new ServerRequest(`https://sp.example.com/saml/slo?${logoutRequestQuery}`);

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(undefined) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'resolveLoginUrl',
      parameters: [`/saml/slo?${logoutRequestQuery}`],
      return: Promise.resolve('https://idp.example.com/sso?SAMLRequest=some-authn-request'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  // the assertion consumer service path as a string: single logout is not enabled, the path is an ordinary one
  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, '/saml/acs');

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(302);
  expect(response.headers.get('location')).toBe('https://idp.example.com/sso?SAMLRequest=some-authn-request');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});
