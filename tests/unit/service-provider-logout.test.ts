import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type * as nodeSaml from '@node-saml/node-saml';
import type { IdpMetadata, IdpMetadataResolver } from '../../src/metadata';
import { createSamlServiceProvider } from '../../src/service-provider';
import { InvalidSamlResponseError } from '../../src/error';

// node-saml resolves a logout response posted to the assertion consumer service with a null profile instead of
// throwing: force that shape to prove it does not pass verification (a logout response belongs to the single logout
// service path)
vi.mock('@node-saml/node-saml', async (importOriginal) => {
  const original = await importOriginal<typeof nodeSaml>();

  class SamlMock extends original.SAML {
    public override async validatePostResponseAsync(): Promise<{ profile: null; loggedOut: boolean }> {
      return { profile: null, loggedOut: true };
    }
  }

  return { ...original, SAML: SamlMock };
});

const metadata: IdpMetadata = {
  entityId: 'https://idp.example.com',
  singleSignOnServiceUrl: 'https://idp.example.com/sso',
  signingCertificates: ['Q2VydDE='],
};

test('verify saml response with logout response', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    entityId: 'https://sp.example.com',
    assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs',
  });

  await expect(samlServiceProvider.verifySamlResponse('some-saml-response')).rejects.toThrow(
    new InvalidSamlResponseError('Logout response instead of an authn response'),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});
