import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type * as nodeSaml from '@node-saml/node-saml';
import type { IdpMetadata, IdpMetadataResolver } from '../../src/metadata';
import { createSamlServiceProvider } from '../../src/service-provider';
import { InvalidSamlResponseError } from '../../src/error';

const profile = {
  issuer: 'https://idp.example.com',
  nameID: 'user@example.com',
  nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
};

// oxlint-disable-next-line functional/no-let
let result: { profile: nodeSaml.Profile | null; loggedOut: boolean } = { profile: null, loggedOut: true };

// node-saml resolves a logout response posted to the assertion consumer service with a null profile instead of
// throwing: force that shape to prove it does not pass verification (a logout response belongs to the single logout
// service path), as well as either half of it on its own
vi.mock('@node-saml/node-saml', async (importOriginal) => {
  const original = await importOriginal<typeof nodeSaml>();

  class SamlMock extends original.SAML {
    public override async validatePostResponseAsync(): Promise<{
      profile: nodeSaml.Profile | null;
      loggedOut: boolean;
    }> {
      return result;
    }
  }

  return { ...original, SAML: SamlMock };
});

const metadata: IdpMetadata = {
  entityId: 'https://idp.example.com',
  singleSignOnServiceUrl: 'https://idp.example.com/sso',
  signingCertificates: ['Q2VydDE='],
};

test.each<{ name: string; result: { profile: nodeSaml.Profile | null; loggedOut: boolean } }>([
  { name: 'logout response', result: { profile: null, loggedOut: true } },
  { name: 'logged out with profile', result: { profile, loggedOut: true } },
  { name: 'missing profile', result: { profile: null, loggedOut: false } },
])('verify saml response with $name', async ({ result: givenResult }) => {
  result = givenResult;

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
