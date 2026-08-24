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
import { createIdpMetadataXml, createSamlResponse, generateIdpKeyMaterial } from '../helper';

const idpEntityId = 'https://idp.example.com';
const spEntityId = 'https://sp.example.com';
const assertionConsumerServiceUrl = 'https://sp.example.com/saml/acs';
const sessionSecret = 'secret-secret-secret-secret-secret-secret';

// oxlint-disable-next-line functional/no-let
let keyMaterial: IdpKeyMaterial;

// oxlint-disable-next-line functional/no-let
let server: Server;

// oxlint-disable-next-line functional/no-let
let metadataUrl: string;

// oxlint-disable-next-line functional/no-let
let singleSignOnServiceUrl: string;

beforeAll(async () => {
  keyMaterial = await generateIdpKeyMaterial();

  server = createServer((request, response) => {
    if (request.url === '/metadata') {
      response.writeHead(200, { 'content-type': 'application/samlmetadata+xml' });
      response.end(
        createIdpMetadataXml({
          entityId: idpEntityId,
          certificates: [keyMaterial.certificate],
          singleSignOnServiceLocation: singleSignOnServiceUrl,
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
