import { beforeEach, describe, expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { useObjectMock } from '@chubbyts/chubbyts-function-mock/dist/object-mock';
import type { Container } from '@chubbyts/chubbyts-dic-types/dist/container';
import type { ConfigFactory } from '@chubbyts/chubbyts-dic-config/dist/dic-config';
import { createContainerByConfigFactory } from '@chubbyts/chubbyts-dic-config/dist/dic-config';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type * as metadata from '../../src/metadata';
import type * as middleware from '../../src/middleware';
import type * as serviceProvider from '../../src/service-provider';
import type * as session from '../../src/session';
import type { IdpMetadataResolver } from '../../src/metadata';
import { createIdpMetadataResolver } from '../../src/metadata';
import { IdpMetadataError } from '../../src/error';
import { createSamlAuthenticationMiddleware } from '../../src/middleware';
import type { SamlServiceProvider } from '../../src/service-provider';
import { createSamlServiceProvider } from '../../src/service-provider';
import type { SamlSession } from '../../src/session';
import { createSamlSession } from '../../src/session';
import type { SamlConfig } from '../../src/service-factory';
import {
  idpMetadataResolverServiceFactory,
  samlAuthenticationMiddlewareServiceFactory,
  samlServiceProviderServiceFactory,
  samlSessionServiceFactory,
} from '../../src/service-factory';

// spies (pass through) to assert what the factories pass to the create functions
vi.mock('../../src/metadata', async (importOriginal) => {
  const original = await importOriginal<typeof metadata>();

  return { ...original, createIdpMetadataResolver: vi.fn(original.createIdpMetadataResolver) };
});

vi.mock('../../src/middleware', async (importOriginal) => {
  const original = await importOriginal<typeof middleware>();

  return { ...original, createSamlAuthenticationMiddleware: vi.fn(original.createSamlAuthenticationMiddleware) };
});

vi.mock('../../src/service-provider', async (importOriginal) => {
  const original = await importOriginal<typeof serviceProvider>();

  return { ...original, createSamlServiceProvider: vi.fn(original.createSamlServiceProvider) };
});

vi.mock('../../src/session', async (importOriginal) => {
  const original = await importOriginal<typeof session>();

  return { ...original, createSamlSession: vi.fn(original.createSamlSession) };
});

const createIdpMetadataResolverMock = vi.mocked(createIdpMetadataResolver);
const createSamlAuthenticationMiddlewareMock = vi.mocked(createSamlAuthenticationMiddleware);
const createSamlServiceProviderMock = vi.mocked(createSamlServiceProvider);
const createSamlSessionMock = vi.mocked(createSamlSession);

beforeEach(() => {
  vi.clearAllMocks();
});

const customFetch: typeof globalThis.fetch = async () => new Response();

const minimalSamlConfig: SamlConfig = {
  idpMetadataUrl: 'https://idp.example.com/metadata',
  entityId: 'https://sp.example.com',
  assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs',
  sessionSecret: 'secret-secret-secret-secret-secret-secret',
};

describe('idpMetadataResolverServiceFactory', () => {
  test('with defaults', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: minimalSamlConfig } } },
    ]);

    const service = idpMetadataResolverServiceFactory()(container);

    expect(createIdpMetadataResolverMock.mock.calls).toStrictEqual([
      [
        'https://idp.example.com/metadata',
        {
          entityId: undefined,
          fetch: undefined,
          maxAge: undefined,
          timeout: undefined,
          cooldown: undefined,
          maxSize: undefined,
        },
      ],
    ]);
    expect(service).toBe(createIdpMetadataResolverMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('with options', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      {
        name: 'get',
        parameters: ['config'],
        return: {
          chubbyts: {
            saml: {
              ...minimalSamlConfig,
              idpEntityId: 'https://idp.example.com',
              fetch: customFetch,
              maxAge: 1800,
              timeout: 10,
              cooldown: 60,
              maxSize: 65536,
              sessionMaxAge: 300,
            },
          },
        },
      },
    ]);

    const service = idpMetadataResolverServiceFactory()(container);

    expect(createIdpMetadataResolverMock.mock.calls).toStrictEqual([
      [
        'https://idp.example.com/metadata',
        {
          entityId: 'https://idp.example.com',
          fetch: customFetch,
          maxAge: 1800,
          timeout: 10,
          cooldown: 60,
          maxSize: 65536,
        },
      ],
    ]);
    expect(service).toBe(createIdpMetadataResolverMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('with name', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      {
        name: 'get',
        parameters: ['config'],
        return: {
          chubbyts: {
            saml: {
              internal: { ...minimalSamlConfig, idpMetadataUrl: 'https://internal-idp.example.com/metadata' },
              partner: { ...minimalSamlConfig, idpMetadataUrl: 'https://partner-idp.example.com/metadata' },
            },
          },
        },
      },
    ]);

    const service = idpMetadataResolverServiceFactory('partner')(container);

    expect(createIdpMetadataResolverMock.mock.calls[0]?.[0]).toBe('https://partner-idp.example.com/metadata');
    expect(service).toBe(createIdpMetadataResolverMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('with name, without named config', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: { internal: minimalSamlConfig } } } },
    ]);

    expect(() => idpMetadataResolverServiceFactory('partner')(container)).toThrow(
      new Error('Missing config "chubbyts.saml.partner.idpMetadataUrl"'),
    );

    expect(createIdpMetadataResolverMock).not.toHaveBeenCalled();

    expect(containerMocks).toHaveLength(0);
  });

  test.each<{ name: string; config: unknown }>([
    { name: 'without chubbyts config', config: {} },
    { name: 'without saml config', config: { chubbyts: {} } },
    { name: 'without idpMetadataUrl', config: { chubbyts: { saml: { entityId: 'https://sp.example.com' } } } },
  ])('$name', ({ config }) => {
    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: config },
    ]);

    expect(() => idpMetadataResolverServiceFactory()(container)).toThrow(
      new Error('Missing config "chubbyts.saml.idpMetadataUrl"'),
    );

    expect(createIdpMetadataResolverMock).not.toHaveBeenCalled();

    expect(containerMocks).toHaveLength(0);
  });
});

describe('samlServiceProviderServiceFactory', () => {
  test('with defaults, without registered samlIdpMetadataResolver', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: minimalSamlConfig } } },
      { name: 'has', parameters: ['samlIdpMetadataResolver'], return: false },
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: minimalSamlConfig } } },
    ]);

    const service = samlServiceProviderServiceFactory()(container);

    expect(createIdpMetadataResolverMock).toHaveBeenCalledTimes(1);

    expect(createSamlServiceProviderMock.mock.calls).toStrictEqual([
      [
        createIdpMetadataResolverMock.mock.results[0]?.value,
        {
          entityId: 'https://sp.example.com',
          assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs',
          clockTolerance: undefined,
          maxAssertionAge: undefined,
          identifierFormat: undefined,
          forceAuthn: undefined,
          wantAssertionsSigned: undefined,
          wantAuthnResponseSigned: undefined,
          validateInResponseTo: undefined,
          authnContext: undefined,
          privateKey: undefined,
          certificate: undefined,
          signatureAlgorithm: undefined,
          decryptionKey: undefined,
        },
      ],
    ]);
    expect(service).toBe(createSamlServiceProviderMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('with options, with registered samlIdpMetadataResolver', () => {
    const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([]);

    const [container, containerMocks] = useObjectMock<Container>([
      {
        name: 'get',
        parameters: ['config'],
        return: {
          chubbyts: {
            saml: {
              ...minimalSamlConfig,
              clockTolerance: 5,
              maxAssertionAge: 300,
              identifierFormat: null,
              forceAuthn: true,
              wantAssertionsSigned: true,
              wantAuthnResponseSigned: false,
              validateInResponseTo: 'ifPresent',
              authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'], comparison: 'minimum' },
              privateKey: 'some-private-key',
              certificate: 'some-certificate',
              signatureAlgorithm: 'sha512',
              decryptionKey: 'some-decryption-key',
              maxAge: 1800,
            },
          },
        },
      },
      { name: 'has', parameters: ['samlIdpMetadataResolver'], return: true },
      { name: 'get', parameters: ['samlIdpMetadataResolver'], return: idpMetadataResolver },
    ]);

    const service = samlServiceProviderServiceFactory()(container);

    expect(createIdpMetadataResolverMock).not.toHaveBeenCalled();

    expect(createSamlServiceProviderMock.mock.calls).toStrictEqual([
      [
        idpMetadataResolver,
        {
          entityId: 'https://sp.example.com',
          assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs',
          clockTolerance: 5,
          maxAssertionAge: 300,
          identifierFormat: null,
          forceAuthn: true,
          wantAssertionsSigned: true,
          wantAuthnResponseSigned: false,
          validateInResponseTo: 'ifPresent',
          authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'], comparison: 'minimum' },
          privateKey: 'some-private-key',
          certificate: 'some-certificate',
          signatureAlgorithm: 'sha512',
          decryptionKey: 'some-decryption-key',
        },
      ],
    ]);
    expect(service).toBe(createSamlServiceProviderMock.mock.results[0]?.value);

    expect(idpMetadataResolverMocks).toHaveLength(0);
    expect(containerMocks).toHaveLength(0);
  });

  test('with name, with registered named samlIdpMetadataResolver', () => {
    const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([]);

    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: { partner: minimalSamlConfig } } } },
      { name: 'has', parameters: ['samlIdpMetadataResolverpartner'], return: true },
      { name: 'get', parameters: ['samlIdpMetadataResolverpartner'], return: idpMetadataResolver },
    ]);

    const service = samlServiceProviderServiceFactory('partner')(container);

    expect(createIdpMetadataResolverMock).not.toHaveBeenCalled();
    expect(createSamlServiceProviderMock.mock.calls[0]?.[0]).toBe(idpMetadataResolver);
    expect(service).toBe(createSamlServiceProviderMock.mock.results[0]?.value);

    expect(idpMetadataResolverMocks).toHaveLength(0);
    expect(containerMocks).toHaveLength(0);
  });

  test('with name, without registered named samlIdpMetadataResolver', () => {
    const config = { chubbyts: { saml: { partner: minimalSamlConfig } } };

    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: config },
      { name: 'has', parameters: ['samlIdpMetadataResolverpartner'], return: false },
      { name: 'get', parameters: ['config'], return: config },
    ]);

    const service = samlServiceProviderServiceFactory('partner')(container);

    expect(createIdpMetadataResolverMock).toHaveBeenCalledTimes(1);
    expect(createSamlServiceProviderMock.mock.calls[0]?.[0]).toBe(createIdpMetadataResolverMock.mock.results[0]?.value);
    expect(service).toBe(createSamlServiceProviderMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('without entityId', () => {
    const { entityId: _, ...samlConfigWithoutEntityId } = minimalSamlConfig;

    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: samlConfigWithoutEntityId } } },
    ]);

    expect(() => samlServiceProviderServiceFactory()(container)).toThrow(
      new Error('Missing config "chubbyts.saml.entityId"'),
    );

    expect(createSamlServiceProviderMock).not.toHaveBeenCalled();

    expect(containerMocks).toHaveLength(0);
  });

  test('without assertionConsumerServiceUrl', () => {
    const { assertionConsumerServiceUrl: _, ...samlConfigWithoutAcsUrl } = minimalSamlConfig;

    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: samlConfigWithoutAcsUrl } } },
    ]);

    expect(() => samlServiceProviderServiceFactory()(container)).toThrow(
      new Error('Missing config "chubbyts.saml.assertionConsumerServiceUrl"'),
    );

    expect(createSamlServiceProviderMock).not.toHaveBeenCalled();

    expect(containerMocks).toHaveLength(0);
  });
});

describe('samlSessionServiceFactory', () => {
  test('with defaults', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: minimalSamlConfig } } },
    ]);

    const service = samlSessionServiceFactory()(container);

    expect(createSamlSessionMock.mock.calls).toStrictEqual([
      [
        {
          secret: 'secret-secret-secret-secret-secret-secret',
          maxAge: undefined,
          cookieName: undefined,
          path: undefined,
          secure: undefined,
          sameSite: undefined,
        },
      ],
    ]);
    expect(service).toBe(createSamlSessionMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('with options', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      {
        name: 'get',
        parameters: ['config'],
        return: {
          chubbyts: {
            saml: {
              ...minimalSamlConfig,
              sessionMaxAge: 300,
              sessionCookieName: 'my-session',
              sessionCookiePath: '/app',
              sessionCookieSecure: false,
              sessionCookieSameSite: 'Strict',
            },
          },
        },
      },
    ]);

    const service = samlSessionServiceFactory()(container);

    expect(createSamlSessionMock.mock.calls).toStrictEqual([
      [
        {
          secret: 'secret-secret-secret-secret-secret-secret',
          maxAge: 300,
          cookieName: 'my-session',
          path: '/app',
          secure: false,
          sameSite: 'Strict',
        },
      ],
    ]);
    expect(service).toBe(createSamlSessionMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('without sessionSecret', () => {
    const { sessionSecret: _, ...samlConfigWithoutSessionSecret } = minimalSamlConfig;

    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: samlConfigWithoutSessionSecret } } },
    ]);

    expect(() => samlSessionServiceFactory()(container)).toThrow(
      new Error('Missing config "chubbyts.saml.sessionSecret"'),
    );

    expect(createSamlSessionMock).not.toHaveBeenCalled();

    expect(containerMocks).toHaveLength(0);
  });
});

describe('samlAuthenticationMiddlewareServiceFactory', () => {
  test('with defaults, without registered services', () => {
    const config = { chubbyts: { saml: minimalSamlConfig } };

    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: config },
      { name: 'has', parameters: ['samlSession'], return: false },
      { name: 'get', parameters: ['config'], return: config },
      { name: 'has', parameters: ['samlServiceProvider'], return: false },
      { name: 'get', parameters: ['config'], return: config },
      { name: 'has', parameters: ['samlIdpMetadataResolver'], return: false },
      { name: 'get', parameters: ['config'], return: config },
      { name: 'has', parameters: ['logger'], return: false },
    ]);

    const service = samlAuthenticationMiddlewareServiceFactory()(container);

    expect(createSamlSessionMock).toHaveBeenCalledTimes(1);
    expect(createIdpMetadataResolverMock).toHaveBeenCalledTimes(1);
    expect(createSamlServiceProviderMock).toHaveBeenCalledTimes(1);

    expect(createSamlAuthenticationMiddlewareMock.mock.calls).toStrictEqual([
      [
        createSamlSessionMock.mock.results[0]?.value,
        createSamlServiceProviderMock.mock.results[0]?.value,
        '/saml/acs',
        undefined,
      ],
    ]);
    expect(service).toBe(createSamlAuthenticationMiddlewareMock.mock.results[0]?.value);

    expect(containerMocks).toHaveLength(0);
  });

  test('with registered services', () => {
    const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
    const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);
    const [logger, loggerMocks] = useObjectMock<Logger>([]);

    const [container, containerMocks] = useObjectMock<Container>([
      {
        name: 'get',
        parameters: ['config'],
        return: { chubbyts: { saml: { assertionConsumerServiceUrl: 'https://sp.example.com/auth/saml/acs' } } },
      },
      { name: 'has', parameters: ['samlSession'], return: true },
      { name: 'get', parameters: ['samlSession'], return: samlSession },
      { name: 'has', parameters: ['samlServiceProvider'], return: true },
      { name: 'get', parameters: ['samlServiceProvider'], return: samlServiceProvider },
      { name: 'has', parameters: ['logger'], return: true },
      { name: 'get', parameters: ['logger'], return: logger },
    ]);

    const service = samlAuthenticationMiddlewareServiceFactory()(container);

    expect(createSamlSessionMock).not.toHaveBeenCalled();
    expect(createIdpMetadataResolverMock).not.toHaveBeenCalled();
    expect(createSamlServiceProviderMock).not.toHaveBeenCalled();

    // the object mocks are proxies which must not be inspected (toStrictEqual would), compare by identity
    expect(createSamlAuthenticationMiddlewareMock.mock.calls).toHaveLength(1);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]).toHaveLength(4);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[0]).toBe(samlSession);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[1]).toBe(samlServiceProvider);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[2]).toBe('/auth/saml/acs');
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[3]).toBe(logger);
    expect(service).toBe(createSamlAuthenticationMiddlewareMock.mock.results[0]?.value);

    expect(samlSessionMocks).toHaveLength(0);
    expect(samlServiceProviderMocks).toHaveLength(0);
    expect(loggerMocks).toHaveLength(0);
    expect(containerMocks).toHaveLength(0);
  });

  test('with name, with registered named services', () => {
    const [samlSession, samlSessionMocks] = useObjectMock<SamlSession>([]);
    const [samlServiceProvider, samlServiceProviderMocks] = useObjectMock<SamlServiceProvider>([]);

    const [container, containerMocks] = useObjectMock<Container>([
      {
        name: 'get',
        parameters: ['config'],
        return: {
          chubbyts: { saml: { partner: { assertionConsumerServiceUrl: 'https://sp.example.com/partner/acs' } } },
        },
      },
      { name: 'has', parameters: ['samlSessionpartner'], return: true },
      { name: 'get', parameters: ['samlSessionpartner'], return: samlSession },
      { name: 'has', parameters: ['samlServiceProviderpartner'], return: true },
      { name: 'get', parameters: ['samlServiceProviderpartner'], return: samlServiceProvider },
      { name: 'has', parameters: ['logger'], return: false },
    ]);

    const service = samlAuthenticationMiddlewareServiceFactory('partner')(container);

    expect(createSamlAuthenticationMiddlewareMock.mock.calls).toHaveLength(1);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[0]).toBe(samlSession);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[1]).toBe(samlServiceProvider);
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[2]).toBe('/partner/acs');
    expect(createSamlAuthenticationMiddlewareMock.mock.calls[0]?.[3]).toBeUndefined();
    expect(service).toBe(createSamlAuthenticationMiddlewareMock.mock.results[0]?.value);

    expect(samlSessionMocks).toHaveLength(0);
    expect(samlServiceProviderMocks).toHaveLength(0);
    expect(containerMocks).toHaveLength(0);
  });

  test('without assertionConsumerServiceUrl', () => {
    const [container, containerMocks] = useObjectMock<Container>([
      { name: 'get', parameters: ['config'], return: { chubbyts: { saml: {} } } },
    ]);

    expect(() => samlAuthenticationMiddlewareServiceFactory()(container)).toThrow(
      new Error('Missing config "chubbyts.saml.assertionConsumerServiceUrl"'),
    );

    expect(createSamlAuthenticationMiddlewareMock).not.toHaveBeenCalled();

    expect(containerMocks).toHaveLength(0);
  });
});

describe('with container by config', () => {
  test('the services are wired together', async () => {
    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      {
        callback: async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
          expect(input).toBe('https://idp.example.com/metadata');
          expect(init?.redirect).toBe('manual');

          return new Response(undefined, { status: 503 });
        },
      },
    ]);

    const container = createContainerByConfigFactory({
      chubbyts: {
        saml: {
          ...minimalSamlConfig,
          fetch,
        } satisfies SamlConfig,
      },
      dependencies: {
        factories: new Map<string, ConfigFactory>([
          ['samlAuthenticationMiddleware', samlAuthenticationMiddlewareServiceFactory()],
          ['samlIdpMetadataResolver', idpMetadataResolverServiceFactory()],
          ['samlServiceProvider', samlServiceProviderServiceFactory()],
          ['samlSession', samlSessionServiceFactory()],
        ]),
      },
    })();

    const samlAuthenticationMiddleware = container.get<Middleware>('samlAuthenticationMiddleware');

    expect(createSamlAuthenticationMiddlewareMock.mock.calls).toStrictEqual([
      [
        container.get<SamlSession>('samlSession'),
        container.get<SamlServiceProvider>('samlServiceProvider'),
        '/saml/acs',
        undefined,
      ],
    ]);

    expect(createSamlServiceProviderMock.mock.calls[0]?.[0]).toBe(
      container.get<IdpMetadataResolver>('samlIdpMetadataResolver'),
    );

    const [handler, handlerMocks] = useFunctionMock<Handler>([]);

    // without a session the configured idp metadata gets resolved through the configured fetch for the login redirect
    await expect(
      samlAuthenticationMiddleware(new ServerRequest('https://sp.example.com/resource'), handler),
    ).rejects.toThrow(
      new IdpMetadataError('Cannot fetch idp metadata from "https://idp.example.com/metadata": status 503'),
    );

    expect(fetchMocks).toHaveLength(0);
    expect(handlerMocks).toHaveLength(0);
  });
});
