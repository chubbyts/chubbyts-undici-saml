import type { Container } from '@chubbyts/chubbyts-dic-types/dist/container';
import type { ResolveConfig } from '@chubbyts/chubbyts-dic-config-factory/dist/dic-config-factory';
import { createAbstractFactory } from '@chubbyts/chubbyts-dic-config-factory/dist/dic-config-factory';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { SamlAssertionIdStore } from './assertion-id-store.js';
import type { IdpMetadataResolver } from './metadata.js';
import { createIdpMetadataResolver } from './metadata.js';
import { createSamlAuthenticationMiddleware } from './middleware.js';
import type { AuthnContext, SamlServiceProvider } from './service-provider.js';
import { createSamlServiceProvider } from './service-provider.js';
import type { SamlSession } from './session.js';
import { createSamlSession } from './session.js';

/**
 * The configuration read by the service factories from `config.chubbyts.saml` (or `config.chubbyts.saml.<name>` for
 * named factories), see the options of `createIdpMetadataResolver`, `createSamlServiceProvider` and
 * `createSamlSession`.
 */
export type SamlConfig = {
  idpMetadataUrl: string;
  entityId: string;
  assertionConsumerServiceUrl: string;
  sessionSecret: string;
  singleLogoutServiceUrl?: string;
  idpEntityId?: string;
  fetch?: typeof globalThis.fetch;
  maxAge?: number;
  timeout?: number;
  cooldown?: number;
  maxSize?: number;
  clockTolerance?: number;
  maxAssertionAge?: number;
  identifierFormat?: string | null;
  forceAuthn?: boolean;
  wantAssertionsSigned?: boolean;
  wantAuthnResponseSigned?: boolean;
  validateInResponseTo?: 'never' | 'ifPresent' | 'always';
  authnContext?: AuthnContext;
  privateKey?: string;
  certificate?: string;
  signatureAlgorithm?: 'sha256' | 'sha512';
  decryptionKey?: string;
  assertionIdStore?: SamlAssertionIdStore;
  sessionMaxAge?: number;
  sessionCookieName?: string;
  sessionCookiePath?: string;
  sessionCookieSecure?: boolean;
  sessionCookieSameSite?: 'Lax' | 'Strict' | 'None';
};

type Config = {
  chubbyts?: {
    saml?: Partial<SamlConfig> | Record<string, Partial<SamlConfig>>;
  };
};

const resolveSamlConfig = (container: Container, resolveConfig: ResolveConfig): Partial<SamlConfig> => {
  return resolveConfig(container.get<Config>('config').chubbyts?.saml ?? {});
};

type RequiredKey = 'idpMetadataUrl' | 'entityId' | 'assertionConsumerServiceUrl' | 'sessionSecret';

const resolveRequiredSamlConfig = <K extends RequiredKey>(
  samlConfig: Partial<SamlConfig>,
  name: string,
  key: K,
): SamlConfig[K] => {
  const value = samlConfig[key];

  if (value === undefined) {
    throw new Error(`Missing config "chubbyts.saml.${name === '' ? '' : `${name}.`}${key}"`);
  }

  return value;
};

export const idpMetadataResolverServiceFactory = createAbstractFactory(
  (container: Container, { name, resolveConfig }): IdpMetadataResolver => {
    const samlConfig = resolveSamlConfig(container, resolveConfig);

    const idpMetadataUrl = resolveRequiredSamlConfig(samlConfig, name, 'idpMetadataUrl');

    const { idpEntityId, fetch, maxAge, timeout, cooldown, maxSize } = samlConfig;

    return createIdpMetadataResolver(idpMetadataUrl, {
      entityId: idpEntityId,
      fetch,
      maxAge,
      timeout,
      cooldown,
      maxSize,
    });
  },
);

export const samlServiceProviderServiceFactory = createAbstractFactory(
  (container: Container, { name, resolveConfig, resolveDependency }): SamlServiceProvider => {
    const samlConfig = resolveSamlConfig(container, resolveConfig);

    const entityId = resolveRequiredSamlConfig(samlConfig, name, 'entityId');
    const assertionConsumerServiceUrl = resolveRequiredSamlConfig(samlConfig, name, 'assertionConsumerServiceUrl');

    const {
      singleLogoutServiceUrl,
      clockTolerance,
      maxAssertionAge,
      identifierFormat,
      forceAuthn,
      wantAssertionsSigned,
      wantAuthnResponseSigned,
      validateInResponseTo,
      authnContext,
      privateKey,
      certificate,
      signatureAlgorithm,
      decryptionKey,
      assertionIdStore,
    } = samlConfig;

    // a registered service wins over the shipped factory, so that any part can be replaced or shared between services
    const idpMetadataResolver = resolveDependency(
      container,
      'samlIdpMetadataResolver',
      idpMetadataResolverServiceFactory,
    );

    return createSamlServiceProvider(idpMetadataResolver, {
      entityId,
      assertionConsumerServiceUrl,
      singleLogoutServiceUrl,
      clockTolerance,
      maxAssertionAge,
      identifierFormat,
      forceAuthn,
      wantAssertionsSigned,
      wantAuthnResponseSigned,
      validateInResponseTo,
      authnContext,
      privateKey,
      certificate,
      signatureAlgorithm,
      decryptionKey,
      assertionIdStore,
    });
  },
);

export const samlSessionServiceFactory = createAbstractFactory(
  (container: Container, { name, resolveConfig }): SamlSession => {
    const samlConfig = resolveSamlConfig(container, resolveConfig);

    const sessionSecret = resolveRequiredSamlConfig(samlConfig, name, 'sessionSecret');

    const { sessionMaxAge, sessionCookieName, sessionCookiePath, sessionCookieSecure, sessionCookieSameSite } =
      samlConfig;

    return createSamlSession({
      secret: sessionSecret,
      maxAge: sessionMaxAge,
      cookieName: sessionCookieName,
      path: sessionCookiePath,
      secure: sessionCookieSecure,
      sameSite: sessionCookieSameSite,
    });
  },
);

export const samlAuthenticationMiddlewareServiceFactory = createAbstractFactory(
  (container: Container, { name, resolveConfig, resolveDependency }): Middleware => {
    const samlConfig = resolveSamlConfig(container, resolveConfig);

    const assertionConsumerServiceUrl = resolveRequiredSamlConfig(samlConfig, name, 'assertionConsumerServiceUrl');

    const { singleLogoutServiceUrl } = samlConfig;

    return createSamlAuthenticationMiddleware(
      resolveDependency(container, 'samlSession', samlSessionServiceFactory),
      resolveDependency(container, 'samlServiceProvider', samlServiceProviderServiceFactory),
      {
        assertionConsumerServicePath: new URL(assertionConsumerServiceUrl).pathname,
        ...(singleLogoutServiceUrl !== undefined
          ? { singleLogoutServicePath: new URL(singleLogoutServiceUrl).pathname }
          : {}),
      },
      container.has('logger') ? container.get<Logger>('logger') : undefined,
    );
  },
);
