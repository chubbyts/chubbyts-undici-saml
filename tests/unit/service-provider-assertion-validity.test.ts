import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { useObjectMock } from '@chubbyts/chubbyts-function-mock/dist/object-mock';
import type * as nodeSaml from '@node-saml/node-saml';
import type { SamlAssertionIdStore } from '../../src/assertion-id-store';
import type { IdpMetadata, IdpMetadataResolver } from '../../src/metadata';
import { createSamlServiceProvider } from '../../src/service-provider';
import { InvalidSamlResponseError } from '../../src/error';

// node-saml requires both NotOnOrAfter (subject confirmation and conditions) and the signature reference needs the
// assertion id, so a real saml response cannot reach the defensive checks of the assertion validity: force the parsed
// assertion node-saml would expose to prove the id and the later NotOnOrAfter are the ones remembered
// oxlint-disable-next-line functional/no-let
let assertion: Record<string, unknown>;

vi.mock('@node-saml/node-saml', async (importOriginal) => {
  const original = await importOriginal<typeof nodeSaml>();

  class SamlMock extends original.SAML {
    public override async validatePostResponseAsync(): Promise<{ profile: nodeSaml.Profile; loggedOut: boolean }> {
      return {
        profile: {
          issuer: 'https://idp.example.com',
          nameID: 'user@example.com',
          nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
          getAssertion: () => assertion,
          getSamlResponseXml: () =>
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com/saml/acs"/>',
        },
        loggedOut: false,
      };
    }
  }

  return { ...original, SAML: SamlMock };
});

const metadata: IdpMetadata = {
  entityId: 'https://idp.example.com',
  singleSignOnServiceUrl: 'https://idp.example.com/sso',
  signingCertificates: ['Q2VydDE='],
};

const options = { entityId: 'https://sp.example.com', assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs' };

const createAssertion = (
  id: string | undefined,
  subjectConfirmationNotOnOrAfter: string | undefined,
  conditionsNotOnOrAfter: string | undefined,
): Record<string, unknown> => ({
  Assertion: {
    ...(id !== undefined ? { $: { ID: id } } : {}),
    Subject: [
      {
        SubjectConfirmation: [
          {
            SubjectConfirmationData: [
              {
                $: {
                  Recipient: 'https://sp.example.com/saml/acs',
                  ...(subjectConfirmationNotOnOrAfter !== undefined
                    ? { NotOnOrAfter: subjectConfirmationNotOnOrAfter }
                    : {}),
                },
              },
            ],
          },
        ],
      },
    ],
    Conditions: [conditionsNotOnOrAfter !== undefined ? { $: { NotOnOrAfter: conditionsNotOnOrAfter } } : {}],
  },
});

test.each<{ name: string; assertion: Record<string, unknown>; expectedExpiresAt: number }>([
  {
    name: 'subject confirmation NotOnOrAfter only',
    assertion: createAssertion('_assertion-1', '2026-01-01T00:05:00Z', undefined),
    expectedExpiresAt: Date.parse('2026-01-01T00:05:00Z'),
  },
  {
    name: 'conditions NotOnOrAfter only',
    assertion: createAssertion('_assertion-1', undefined, '2026-01-01T00:05:00Z'),
    expectedExpiresAt: Date.parse('2026-01-01T00:05:00Z'),
  },
  {
    name: 'later subject confirmation NotOnOrAfter',
    assertion: createAssertion('_assertion-1', '2026-01-01T00:10:00Z', '2026-01-01T00:05:00Z'),
    expectedExpiresAt: Date.parse('2026-01-01T00:10:00Z'),
  },
  {
    name: 'later conditions NotOnOrAfter',
    assertion: createAssertion('_assertion-1', '2026-01-01T00:05:00Z', '2026-01-01T00:10:00Z'),
    expectedExpiresAt: Date.parse('2026-01-01T00:10:00Z'),
  },
])('verify saml response with assertion validity: $name', async ({ assertion: givenAssertion, expectedExpiresAt }) => {
  assertion = givenAssertion;

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const [assertionIdStore, assertionIdStoreMocks] = useObjectMock<SamlAssertionIdStore>([
    { name: 'consume', parameters: ['_assertion-1', expectedExpiresAt], return: Promise.resolve(true) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, assertionIdStore });

  expect(await samlServiceProvider.verifySamlResponse('some-saml-response')).toEqual({
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    issuer: 'https://idp.example.com',
    attributes: {},
  });

  expect(idpMetadataResolverMocks).toHaveLength(0);
  expect(assertionIdStoreMocks).toHaveLength(0);
});

test.each<{ name: string; assertion: Record<string, unknown>; message?: string }>([
  { name: 'missing id', assertion: createAssertion(undefined, '2026-01-01T00:05:00Z', '2026-01-01T00:05:00Z') },
  { name: 'empty id', assertion: createAssertion('', '2026-01-01T00:05:00Z', '2026-01-01T00:05:00Z') },
  { name: 'missing NotOnOrAfter', assertion: createAssertion('_assertion-1', undefined, undefined) },
  {
    name: 'missing assertion',
    assertion: {},
    message: 'Recipient mismatch: expected "https://sp.example.com/saml/acs", given "undefined"',
  },
])('verify saml response with invalid assertion validity: $name', async ({ assertion: givenAssertion, message }) => {
  assertion = givenAssertion;

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const [assertionIdStore, assertionIdStoreMocks] = useObjectMock<SamlAssertionIdStore>([]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, assertionIdStore });

  await expect(samlServiceProvider.verifySamlResponse('some-saml-response')).rejects.toThrow(
    new InvalidSamlResponseError(message ?? 'Missing ID or NotOnOrAfter within assertion'),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
  expect(assertionIdStoreMocks).toHaveLength(0);
});
