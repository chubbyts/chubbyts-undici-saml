import { expect, test } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { useObjectMock } from '@chubbyts/chubbyts-function-mock/dist/object-mock';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { BodyInit, Handler } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { InvalidSamlResponseError } from '../../src/error';
import type { SamlIdentity, SamlServiceProvider } from '../../src/service-provider';
import type { SamlSession } from '../../src/session';
import { MAX_SAML_RESPONSE_SIZE, createSamlAuthenticationMiddleware } from '../../src/middleware';

const assertionConsumerServicePath = '/saml/acs';

const identity: SamlIdentity = {
  nameId: 'user@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  sessionIndex: '_session-1',
  issuer: 'https://idp.example.com',
  attributes: { email: 'user@example.com' },
};

test('with invalid assertionConsumerServicePath', () => {
  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  expect(() => createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, 'saml/acs')).toThrow(
    'Invalid assertionConsumerServicePath "saml/acs": must start with "/"',
  );

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
});

test('with session', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/resource', { attributes: { key: 'value' } });

  const handlerResponse = new Response('OK');

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([
    {
      callback: async (handledServerRequest: ServerRequest): Promise<Response> => {
        expect(handledServerRequest).not.toBe(serverRequest);
        expect(handledServerRequest.url).toBe(serverRequest.url);
        expect(handledServerRequest.attributes).toEqual({ key: 'value', saml: { identity } });

        return handlerResponse;
      },
    },
  ]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response).toBe(handlerResponse);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with session on assertion consumer service path without post', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs');

  const handlerResponse = new Response('OK');

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(identity) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([
    { callback: async (): Promise<Response> => handlerResponse },
  ]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response).toBe(handlerResponse);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('without session', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/resource?key=value');

  const loginUrl = 'https://idp.example.com/sso?SAMLRequest=some-request&RelayState=%2Fresource%3Fkey%3Dvalue';

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(undefined) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'resolveLoginUrl', parameters: ['/resource?key=value'], return: Promise.resolve(loginUrl) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(302);
  expect(response.statusText).toBe('Found');
  expect(Object.fromEntries(response.headers.entries())).toEqual({ 'cache-control': 'no-store', location: loginUrl });

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('without session with head request', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/resource', { method: 'HEAD' });

  const loginUrl = 'https://idp.example.com/sso?SAMLRequest=some-request';

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(undefined) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'resolveLoginUrl', parameters: ['/resource'], return: Promise.resolve(loginUrl) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(302);
  expect(Object.fromEntries(response.headers.entries())).toEqual({ 'cache-control': 'no-store', location: loginUrl });

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('without session with none navigation request', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/resource', { method: 'POST', body: 'some-body' });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'resolveIdentity', parameters: [serverRequest], return: Promise.resolve(undefined) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({ 'cache-control': 'no-store' });

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

// a body of unknown length (chunked transfer encoding): the size is only known while reading it
const createChunkedBody = (chunk: string, count: number): ReadableStream<Uint8Array> => {
  // oxlint-disable-next-line functional/no-let
  let sent = 0;

  return new ReadableStream<Uint8Array>({
    pull: (controller): void => {
      if (sent === count) {
        controller.close();

        return;
      }

      sent += 1;
      controller.enqueue(new TextEncoder().encode(chunk));
    },
  });
};

test.each<{ name: string; body: BodyInit; headers?: Record<string, string> }>([
  {
    name: 'form body',
    body: new URLSearchParams({ SAMLResponse: 'some-saml-response', RelayState: '/resource?key=value' }),
  },
  {
    // the media type is matched case insensitively and without its parameters
    name: 'chunked form body',
    body: createChunkedBody('SAMLResponse=some-saml-response&RelayState=%2Fresource%3Fkey%3Dvalue', 1),
    headers: { 'content-type': 'Application/X-WWW-Form-Urlencoded ; charset=utf-8' },
  },
])('with saml response: $name', async ({ body, headers }) => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs', {
    method: 'POST',
    body,
    headers,
    duplex: 'half',
  });

  const cookie = 'saml-session=some-jwt; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=3600';

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'createCookie', parameters: [identity], return: Promise.resolve(cookie) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifySamlResponse', parameters: ['some-saml-response'], return: Promise.resolve(identity) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(303);
  expect(response.statusText).toBe('See Other');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'cache-control': 'no-store',
    location: '/resource?key=value',
    'set-cookie': cookie,
  });

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test.each<{ name: string; relayState: string | undefined }>([
  { name: 'missing', relayState: undefined },
  { name: 'empty', relayState: '' },
  { name: 'absolute url', relayState: 'https://evil.example.com/target' },
  { name: 'protocol relative url', relayState: '//evil.example.com/target' },
  { name: 'backslash url', relayState: '/\\evil.example.com/target' },
  { name: 'control character', relayState: '/target\u0000' },
  { name: 'whitespace', relayState: '/target path' },
])('with saml response and unsafe relay state: $name', async ({ relayState }) => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs', {
    method: 'POST',
    body: new URLSearchParams({
      SAMLResponse: 'some-saml-response',
      ...(relayState !== undefined ? { RelayState: relayState } : {}),
    }),
  });

  const cookie = 'saml-session=some-jwt; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=3600';

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([
    { name: 'createCookie', parameters: [identity], return: Promise.resolve(cookie) },
  ]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifySamlResponse', parameters: ['some-saml-response'], return: Promise.resolve(identity) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(303);
  expect(response.headers.get('location')).toBe('/');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test.each<{ name: string; body: BodyInit; headers?: Record<string, string> }>([
  {
    name: 'by content length',
    body: 'SAMLResponse=x',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': String(MAX_SAML_RESPONSE_SIZE + 1),
    },
  },
  {
    name: 'by saml response parameter',
    body: new URLSearchParams({ SAMLResponse: 'x'.repeat(MAX_SAML_RESPONSE_SIZE + 1) }),
  },
  {
    name: 'by chunked body',
    body: createChunkedBody(`SAMLResponse=${'x'.repeat(65_536)}`, 5),
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  },
])('with too large saml response: $name', async ({ body, headers }) => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs', {
    method: 'POST',
    body,
    headers,
    duplex: 'half',
  });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);
  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(413);
  expect(response.statusText).toBe('Content Too Large');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  });
  expect(await response.text()).toBe('The saml response exceeds the maximum size');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test.each<{ name: string; body: BodyInit | undefined; headers?: Record<string, string> }>([
  { name: 'without body', body: undefined },
  {
    name: 'without body and with form content type',
    body: undefined,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  },
  {
    name: 'with none form body',
    body: JSON.stringify({ key: 'value' }),
    headers: { 'content-type': 'application/json' },
  },
  {
    name: 'with chunked form body',
    body: createChunkedBody('RelayState=%2Fresource', 1),
    headers: { 'content-type': 'Application/X-WWW-Form-Urlencoded ; charset=utf-8' },
  },
  {
    name: 'with none form content type',
    body: 'SAMLResponse=x',
    headers: { 'content-type': 'text/plain' },
  },
  {
    name: 'with content length equal to the maximum size',
    body: 'RelayState=%2Fresource',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(MAX_SAML_RESPONSE_SIZE) },
  },
  {
    name: 'with form body of the maximum size',
    body: `RelayState=${'x'.repeat(MAX_SAML_RESPONSE_SIZE - 'RelayState='.length)}`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  },
  { name: 'without saml response parameter', body: new URLSearchParams({ RelayState: '/resource' }) },
  { name: 'with empty saml response parameter', body: new URLSearchParams({ SAMLResponse: '' }) },
])('with missing saml response: $name', async ({ body, headers }) => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs', {
    method: 'POST',
    body,
    headers,
    duplex: 'half',
  });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);
  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(400);
  expect(response.statusText).toBe('Bad Request');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  });
  expect(await response.text()).toBe('Missing "SAMLResponse" parameter');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with invalid saml response', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs?key=value', {
    method: 'POST',
    body: new URLSearchParams({ SAMLResponse: 'some-saml-response' }),
  });

  const cause = new Error('Invalid signature');

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'verifySamlResponse',
      parameters: ['some-saml-response'],
      error: new InvalidSamlResponseError('Invalid signature', cause),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const [logger, loggerMocks] = useObjectMock<Logger>([
    {
      name: 'info',
      parameters: [
        'Invalid saml response',
        {
          method: 'POST',
          // the query string is left out on purpose: it may carry sensitive data
          pathname: '/saml/acs',
          error: { name: 'InvalidSamlResponseError', message: 'Invalid signature', cause },
        },
      ],
    },
  ]);

  const middleware = createSamlAuthenticationMiddleware(
    samlSession,
    samlServiceProvider,
    assertionConsumerServicePath,
    logger,
  );

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(403);
  expect(response.statusText).toBe('Forbidden');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  });
  expect(await response.text()).toBe('The saml response is invalid or expired');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});

test('with invalid saml response and default logger', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs', {
    method: 'POST',
    body: new URLSearchParams({ SAMLResponse: 'some-saml-response' }),
  });

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    {
      name: 'verifySamlResponse',
      parameters: ['some-saml-response'],
      error: new InvalidSamlResponseError('Invalid signature'),
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, assertionConsumerServicePath);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(403);
  expect(await response.text()).toBe('The saml response is invalid or expired');

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with failing saml response verifier', async () => {
  const serverRequest = new ServerRequest('https://sp.example.com/saml/acs', {
    method: 'POST',
    body: new URLSearchParams({ SAMLResponse: 'some-saml-response' }),
  });

  const error = new Error('Cannot fetch idp metadata from "https://idp.example.com/metadata": status 500');

  const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);

  const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([
    { name: 'verifySamlResponse', parameters: ['some-saml-response'], error },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const [logger, loggerMocks] = useObjectMock<Logger>([]);

  const middleware = createSamlAuthenticationMiddleware(
    samlSession,
    samlServiceProvider,
    assertionConsumerServicePath,
    logger,
  );

  await expect(middleware(serverRequest, handler)).rejects.toBe(error);

  expect(samlSessionMocks).toHaveLength(0);
  expect(samlServiceProviderMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});
