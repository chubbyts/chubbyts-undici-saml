import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type * as nodeSaml from '@node-saml/node-saml';
import type { IdpMetadata, IdpMetadataResolver } from '../../src/metadata';
import { createSamlServiceProvider } from '../../src/service-provider';

const samlConstructed = vi.hoisted(() => vi.fn());

// the saml instance is created per metadata: count the constructions to prove it is reused as long as the metadata
// stays the same
vi.mock('@node-saml/node-saml', async (importOriginal) => {
  const original = await importOriginal<typeof nodeSaml>();

  class SamlMock extends original.SAML {
    public constructor(...args: ConstructorParameters<typeof original.SAML>) {
      super(...args);

      samlConstructed();
    }
  }

  return { ...original, SAML: SamlMock };
});

const metadata: IdpMetadata = {
  entityId: 'https://idp.example.com',
  singleSignOnServiceUrl: 'https://idp.example.com/sso',
  signingCertificates: ['Q2VydDE='],
};

test('resolve login url reuses the saml instance per metadata', async () => {
  const rotatedMetadata: IdpMetadata = { ...metadata, signingCertificates: ['Q2VydDI='] };

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(rotatedMetadata) },
    { parameters: [], return: Promise.resolve(rotatedMetadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    entityId: 'https://sp.example.com',
    assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs',
  });

  await samlServiceProvider.resolveLoginUrl('/');
  await samlServiceProvider.resolveLoginUrl('/');

  expect(samlConstructed).toHaveBeenCalledTimes(1);

  await samlServiceProvider.resolveLoginUrl('/');
  await samlServiceProvider.resolveLoginUrl('/');

  expect(samlConstructed).toHaveBeenCalledTimes(2);

  expect(idpMetadataResolverMocks).toHaveLength(0);
});
