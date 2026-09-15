import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, expect, test } from 'vitest';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { createIdpMetadataResolver } from '../../src/metadata';
import { createSamlAuthenticationMiddleware } from '../../src/middleware';
import type { SamlServiceProviderOptions } from '../../src/service-provider';
import { createSamlServiceProvider } from '../../src/service-provider';
import { createSamlSession } from '../../src/session';
import type { IdpKeyMaterial } from '../helper';
import {
  createIdpMetadataXml,
  createLogoutRequestXml,
  createLogoutResponseXml,
  createRedirectQuery,
  createSamlResponse,
  generateIdpKeyMaterial,
  inflateRedirectMessage,
} from '../helper';

const idpEntityId = 'https://idp.example.com';
const spEntityId = 'https://sp.example.com';
const assertionConsumerServiceUrl = 'https://sp.example.com/saml/acs';
const singleLogoutServiceUrl = 'https://sp.example.com/saml/slo';
const sessionSecret = 'secret-secret-secret-secret-secret-secret';

// oxlint-disable-next-line functional/no-let
let keyMaterial: IdpKeyMaterial;

// oxlint-disable-next-line functional/no-let
let spKeyMaterial: IdpKeyMaterial;

// oxlint-disable-next-line functional/no-let
let server: Server;

// oxlint-disable-next-line functional/no-let
let metadataUrl: string;

// oxlint-disable-next-line functional/no-let
let singleSignOnServiceUrl: string;

// oxlint-disable-next-line functional/no-let
let idpSingleLogoutServiceUrl: string;

beforeAll(async () => {
  keyMaterial = await generateIdpKeyMaterial();
  spKeyMaterial = await generateIdpKeyMaterial();

  server = createServer((request, response) => {
    if (request.url === '/metadata') {
      response.writeHead(200, { 'content-type': 'application/samlmetadata+xml' });
      response.end(
        createIdpMetadataXml({
          entityId: idpEntityId,
          certificates: [keyMaterial.certificate],
          singleSignOnServiceLocation: singleSignOnServiceUrl,
          singleLogoutServiceLocation: idpSingleLogoutServiceUrl,
        }),
      );

      return;
    }

    response.writeHead(404);
    response.end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const { port } = server.address() as AddressInfo;

  metadataUrl = `http://127.0.0.1:${port}/metadata`;
  singleSignOnServiceUrl = `http://127.0.0.1:${port}/sso`;
  idpSingleLogoutServiceUrl = `http://127.0.0.1:${port}/slo`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

const handler: Handler = async (serverRequest: ServerRequest): Promise<Response> => {
  return new Response(JSON.stringify(serverRequest.attributes.saml), {
    headers: { 'content-type': 'application/json' },
  });
};

const createMiddleware = (options: Partial<SamlServiceProviderOptions> = {}): Middleware => {
  return createSamlAuthenticationMiddleware(
    createSamlSession({ secret: sessionSecret }),
    createSamlServiceProvider(createIdpMetadataResolver(metadataUrl), {
      entityId: spEntityId,
      assertionConsumerServiceUrl,
      ...options,
    }),
    '/saml/acs',
  );
};

const createSingleLogoutMiddleware = (): Middleware => {
  return createSamlAuthenticationMiddleware(
    createSamlSession({ secret: sessionSecret }),
    createSamlServiceProvider(createIdpMetadataResolver(metadataUrl), {
      entityId: spEntityId,
      assertionConsumerServiceUrl,
      singleLogoutServiceUrl,
      privateKey: spKeyMaterial.privateKey,
      certificate: spKeyMaterial.certificatePem,
    }),
    { assertionConsumerServicePath: '/saml/acs', singleLogoutServicePath: '/saml/slo' },
  );
};

// the session cookie of a login through the assertion consumer service
const login = async (middleware: Middleware, sessionIndex: string): Promise<string> => {
  const response = await middleware(
    new ServerRequest('https://sp.example.com/saml/acs', {
      method: 'POST',
      body: new URLSearchParams({
        SAMLResponse: createSamlResponse(keyMaterial, {
          idpEntityId,
          spEntityId,
          assertionConsumerServiceUrl,
          sessionIndex,
          signResponse: true,
        }),
      }),
    }),
    handler,
  );

  expect(response.status).toBe(303);

  return (response.headers.get('set-cookie') as string).split(';')[0] as string;
};

test('login, assertion consumer service, authenticated request', async () => {
  const middleware = createMiddleware();

  // 1. an unauthenticated navigation request gets redirected to the identity provider
  const loginResponse = await middleware(new ServerRequest('https://sp.example.com/resource?key=value'), handler);

  expect(loginResponse.status).toBe(302);

  const loginUrl = new URL(loginResponse.headers.get('location') as string);

  expect(`${loginUrl.origin}${loginUrl.pathname}`).toBe(singleSignOnServiceUrl);
  expect(loginUrl.searchParams.get('SAMLRequest')).not.toBeNull();
  expect(loginUrl.searchParams.get('RelayState')).toBe('/resource?key=value');

  // 2. the identity provider answers with a saml response posted to the assertion consumer service
  const samlResponse = createSamlResponse(keyMaterial, {
    idpEntityId,
    spEntityId,
    assertionConsumerServiceUrl,
    sessionIndex: '_session-1',
    attributes: { email: ['user@example.com'], roles: ['admin', 'user'] },
    signResponse: true,
  });

  const assertionConsumerServiceResponse = await middleware(
    new ServerRequest('https://sp.example.com/saml/acs', {
      method: 'POST',
      body: new URLSearchParams({
        SAMLResponse: samlResponse,
        RelayState: loginUrl.searchParams.get('RelayState') as string,
      }),
    }),
    handler,
  );

  expect(assertionConsumerServiceResponse.status).toBe(303);
  expect(assertionConsumerServiceResponse.headers.get('location')).toBe('/resource?key=value');

  const cookie = assertionConsumerServiceResponse.headers.get('set-cookie') as string;

  expect(cookie).toMatch(/^saml-session=[\w-.]+; Path=\/; HttpOnly; SameSite=Lax; Secure; Max-Age=3600$/);

  // 3. with the session cookie the request reaches the handler
  const authenticatedResponse = await middleware(
    new ServerRequest('https://sp.example.com/resource?key=value', {
      headers: { cookie: cookie.split(';')[0] as string },
    }),
    handler,
  );

  expect(authenticatedResponse.status).toBe(200);

  expect(await authenticatedResponse.json()).toEqual({
    identity: {
      nameId: 'user@example.com',
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      sessionIndex: '_session-1',
      authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      issuer: idpEntityId,
      attributes: { email: 'user@example.com', roles: ['admin', 'user'] },
    },
  });
});

test('with replayed saml response', async () => {
  const middleware = createMiddleware();

  const samlResponse = createSamlResponse(keyMaterial, {
    idpEntityId,
    spEntityId,
    assertionConsumerServiceUrl,
    signResponse: true,
  });

  const createRequest = (): ServerRequest =>
    new ServerRequest('https://sp.example.com/saml/acs', {
      method: 'POST',
      body: new URLSearchParams({ SAMLResponse: samlResponse }),
    });

  expect((await middleware(createRequest(), handler)).status).toBe(303);

  const response = await middleware(createRequest(), handler);

  expect(response.status).toBe(403);
  expect(await response.text()).toBe('The saml response is invalid or expired');
});

test('with invalid saml response', async () => {
  const middleware = createMiddleware();

  const otherKeyMaterial = await generateIdpKeyMaterial();

  const samlResponse = createSamlResponse(otherKeyMaterial, {
    idpEntityId,
    spEntityId,
    assertionConsumerServiceUrl,
    signResponse: true,
  });

  const response = await middleware(
    new ServerRequest('https://sp.example.com/saml/acs', {
      method: 'POST',
      body: new URLSearchParams({ SAMLResponse: samlResponse }),
    }),
    handler,
  );

  expect(response.status).toBe(403);
  expect(await response.text()).toBe('The saml response is invalid or expired');
});

test('with missing saml response', async () => {
  const middleware = createMiddleware();

  const response = await middleware(
    new ServerRequest('https://sp.example.com/saml/acs', {
      method: 'POST',
      body: new URLSearchParams({ RelayState: '/resource' }),
    }),
    handler,
  );

  expect(response.status).toBe(400);
  expect(await response.text()).toBe('Missing "SAMLResponse" parameter');
});

test('with unauthenticated none navigation request', async () => {
  const middleware = createMiddleware();

  const response = await middleware(
    new ServerRequest('https://sp.example.com/resource', { method: 'POST', body: 'some-body' }),
    handler,
  );

  expect(response.status).toBe(401);
});

test('service provider initiated single logout', async () => {
  const middleware = createSingleLogoutMiddleware();

  const cookie = await login(middleware, '_session-1');

  // 1. the logout removes the session and redirects to the identity provider with a signed logout request
  const logoutResponse = await middleware(
    new ServerRequest('https://sp.example.com/saml/slo', {
      method: 'POST',
      headers: { cookie },
      body: new URLSearchParams({ RelayState: '/goodbye' }),
    }),
    handler,
  );

  expect(logoutResponse.status).toBe(303);
  expect(logoutResponse.headers.get('set-cookie')).toBe(
    'saml-session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0',
  );

  const logoutUrl = new URL(logoutResponse.headers.get('location') as string);

  expect(`${logoutUrl.origin}${logoutUrl.pathname}`).toBe(idpSingleLogoutServiceUrl);
  expect(logoutUrl.searchParams.get('RelayState')).toBe('/goodbye');
  expect(logoutUrl.searchParams.get('Signature')).not.toBeNull();

  const logoutRequest = inflateRedirectMessage(logoutUrl, 'SAMLRequest');

  expect(logoutRequest).toContain('<samlp:LogoutRequest');
  expect(logoutRequest).toContain('>user@example.com</saml:NameID>');
  expect(logoutRequest).toContain('>_session-1</saml2p:SessionIndex>');

  const [, logoutRequestId] = /ID="([^"]+)"/.exec(logoutRequest) as RegExpExecArray;

  // 2. the identity provider answers with a signed logout response, the browser gets sent to the relay state
  const query = createRedirectQuery(
    keyMaterial,
    'SAMLResponse',
    createLogoutResponseXml({ idpEntityId, destination: singleLogoutServiceUrl, inResponseTo: logoutRequestId }),
    { relayState: logoutUrl.searchParams.get('RelayState') as string },
  );

  const logoutResponseResponse = await middleware(
    new ServerRequest(`https://sp.example.com/saml/slo?${query}`),
    handler,
  );

  expect(logoutResponseResponse.status).toBe(303);
  expect(logoutResponseResponse.headers.get('location')).toBe('/goodbye');
  expect(logoutResponseResponse.headers.get('set-cookie')).toBe(
    'saml-session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0',
  );

  // 3. without the session the request gets redirected to the identity provider again
  const response = await middleware(new ServerRequest('https://sp.example.com/resource'), handler);

  expect(response.status).toBe(302);
});

test('identity provider initiated single logout', async () => {
  const middleware = createSingleLogoutMiddleware();

  const cookie = await login(middleware, '_session-1');

  // the identity provider sends a signed logout request for the session, the session gets removed and the browser is
  // sent back to the identity provider with a signed logout response
  const query = createRedirectQuery(
    keyMaterial,
    'SAMLRequest',
    createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl, sessionIndex: '_session-1' }),
    { relayState: 'idp-relay-state' },
  );

  const response = await middleware(
    new ServerRequest(`https://sp.example.com/saml/slo?${query}`, { headers: { cookie } }),
    handler,
  );

  expect(response.status).toBe(303);
  expect(response.headers.get('set-cookie')).toBe('saml-session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0');

  const logoutResponseUrl = new URL(response.headers.get('location') as string);

  expect(`${logoutResponseUrl.origin}${logoutResponseUrl.pathname}`).toBe(idpSingleLogoutServiceUrl);
  expect(logoutResponseUrl.searchParams.get('RelayState')).toBe('idp-relay-state');
  expect(logoutResponseUrl.searchParams.get('Signature')).not.toBeNull();

  const logoutResponse = inflateRedirectMessage(logoutResponseUrl, 'SAMLResponse');

  expect(logoutResponse).toContain('<samlp:LogoutResponse');
  expect(logoutResponse).toContain('InResponseTo="_logout-request-1"');
  expect(logoutResponse).toContain('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>');
});

test('identity provider initiated single logout for another session', async () => {
  const middleware = createSingleLogoutMiddleware();

  const cookie = await login(middleware, '_session-1');

  const query = createRedirectQuery(
    keyMaterial,
    'SAMLRequest',
    createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl, sessionIndex: '_session-2' }),
  );

  const response = await middleware(
    new ServerRequest(`https://sp.example.com/saml/slo?${query}`, { headers: { cookie } }),
    handler,
  );

  // the session is kept and the identity provider gets a failure response
  expect(response.status).toBe(303);
  expect(response.headers.get('set-cookie')).toBeNull();

  const logoutResponse = inflateRedirectMessage(new URL(response.headers.get('location') as string), 'SAMLResponse');

  expect(logoutResponse).toContain('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">');

  const authenticatedResponse = await middleware(
    new ServerRequest('https://sp.example.com/resource', { headers: { cookie } }),
    handler,
  );

  expect(authenticatedResponse.status).toBe(200);
});

test('with unsigned logout request', async () => {
  const middleware = createSingleLogoutMiddleware();

  const query = createRedirectQuery(
    keyMaterial,
    'SAMLRequest',
    createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl }),
    { sign: false },
  );

  const response = await middleware(new ServerRequest(`https://sp.example.com/saml/slo?${query}`), handler);

  expect(response.status).toBe(403);
  expect(await response.text()).toBe('The saml logout request is invalid or expired');
});
