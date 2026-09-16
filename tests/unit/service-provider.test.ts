import { Buffer } from 'node:buffer';
import { inflateRawSync } from 'node:zlib';
import { SAML } from '@node-saml/node-saml';
import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { useObjectMock } from '@chubbyts/chubbyts-function-mock/dist/object-mock';
import type { IdpMetadata, IdpMetadataResolver } from '../../src/metadata';
import type { SamlServiceProviderOptions } from '../../src/service-provider';
import { createSamlServiceProvider } from '../../src/service-provider';
import { InvalidSamlResponseError } from '../../src/error';
import type { SamlAssertionIdStore } from '../../src/assertion-id-store';
import { createSamlResponse, loadKeyMaterial } from '../helper';

const idpEntityId = 'https://idp.example.com';
const spEntityId = 'https://sp.example.com';
const assertionConsumerServiceUrl = 'https://sp.example.com/saml/acs';
const singleSignOnServiceUrl = 'https://idp.example.com/sso';

const keyMaterial = loadKeyMaterial('idp');

const metadata: IdpMetadata = {
  entityId: idpEntityId,
  singleSignOnServiceUrl,
  signingCertificates: [keyMaterial.certificate],
};

const options: SamlServiceProviderOptions = { entityId: spEntityId, assertionConsumerServiceUrl };

const responseOptions = { idpEntityId, spEntityId, assertionConsumerServiceUrl, signResponse: true };

const expectInvalidSamlResponseError = async (promise: Promise<unknown>): Promise<InvalidSamlResponseError> => {
  const error: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );

  expect(error).toBeInstanceOf(InvalidSamlResponseError);
  expect((error as InvalidSamlResponseError).name).toBe('InvalidSamlResponseError');

  return error as InvalidSamlResponseError;
};

test.each<{ name: string; options: SamlServiceProviderOptions; message: string }>([
  {
    name: 'missing entityId',
    options: { ...options, entityId: undefined as unknown as string },
    message: 'Invalid entityId: must be a non-empty string',
  },
  {
    name: 'empty entityId',
    options: { ...options, entityId: '' },
    message: 'Invalid entityId: must be a non-empty string',
  },
  {
    name: 'missing assertionConsumerServiceUrl',
    options: { ...options, assertionConsumerServiceUrl: undefined as unknown as string },
    message: 'Invalid assertionConsumerServiceUrl "undefined": must be an absolute http(s) url',
  },
  {
    name: 'relative assertionConsumerServiceUrl',
    options: { ...options, assertionConsumerServiceUrl: '/saml/acs' },
    message: 'Invalid assertionConsumerServiceUrl "/saml/acs": must be an absolute http(s) url',
  },
  {
    name: 'assertionConsumerServiceUrl with embedded credentials',
    options: { ...options, assertionConsumerServiceUrl: 'https://user:pass@sp.example.com/saml/acs' },
    message:
      'Invalid assertionConsumerServiceUrl "https://user:pass@sp.example.com/saml/acs": must be an absolute http(s) url',
  },
  {
    name: 'negative clockTolerance',
    options: { ...options, clockTolerance: -1 },
    message: 'Invalid clockTolerance -1: must be a non-negative number of seconds',
  },
  {
    name: 'not a number maxAssertionAge',
    options: { ...options, maxAssertionAge: Number.NaN },
    message: 'Invalid maxAssertionAge NaN: must be a non-negative number of seconds',
  },
  {
    name: 'invalid validateInResponseTo',
    options: { ...options, validateInResponseTo: 'sometimes' as 'never' },
    message: 'Invalid validateInResponseTo "sometimes": must be one of "never", "ifPresent", "always"',
  },
  {
    name: 'null authnContext',
    options: { ...options, authnContext: null as unknown as { classRefs: Array<string> } },
    message: 'Invalid authnContext: classRefs must be a non-empty array of non-empty strings',
  },
  {
    name: 'authnContext without classRefs',
    options: { ...options, authnContext: {} as { classRefs: Array<string> } },
    message: 'Invalid authnContext: classRefs must be a non-empty array of non-empty strings',
  },
  {
    name: 'authnContext with empty classRefs',
    options: { ...options, authnContext: { classRefs: [] } },
    message: 'Invalid authnContext: classRefs must be a non-empty array of non-empty strings',
  },
  {
    name: 'authnContext with empty classRef',
    options: { ...options, authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos', ''] } },
    message: 'Invalid authnContext: classRefs must be a non-empty array of non-empty strings',
  },
  {
    name: 'authnContext with invalid comparison',
    options: {
      ...options,
      authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'], comparison: 'best' as 'exact' },
    },
    message: 'Invalid authnContext.comparison "best": must be one of "exact", "minimum", "maximum", "better"',
  },
  {
    name: 'unsupported signatureAlgorithm',
    options: { ...options, signatureAlgorithm: 'sha1' as 'sha256' },
    message: 'Unsupported signatureAlgorithm "sha1", supported algorithms are "sha256", "sha512"',
  },
])('create service provider with invalid option: $name', ({ options: invalidOptions, message }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([]);

  expect(() => createSamlServiceProvider(idpMetadataResolver, invalidOptions)).toThrow(message);

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('resolve login url', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const loginUrl = new URL(await samlServiceProvider.resolveLoginUrl('/resource?key=value'));

  expect(`${loginUrl.origin}${loginUrl.pathname}`).toBe(singleSignOnServiceUrl);
  expect(loginUrl.searchParams.get('RelayState')).toBe('/resource?key=value');

  const authnRequest = inflateRawSync(
    Buffer.from(loginUrl.searchParams.get('SAMLRequest') as string, 'base64'),
  ).toString();

  expect(authnRequest).toContain('AuthnRequest');
  expect(authnRequest).toContain(`Destination="${singleSignOnServiceUrl}"`);
  expect(authnRequest).toContain(`AssertionConsumerServiceURL="${assertionConsumerServiceUrl}"`);
  expect(authnRequest).toContain(`>${spEntityId}</saml:Issuer>`);
  expect(authnRequest).not.toContain('RequestedAuthnContext');
  expect(loginUrl.searchParams.get('SigAlg')).toBeNull();

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test.each<{
  name: string;
  options: Partial<SamlServiceProviderOptions>;
  expectedFormat: string | undefined;
  expectedForceAuthn: boolean;
}>([
  {
    name: 'defaults',
    options: {},
    expectedFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    expectedForceAuthn: false,
  },
  {
    name: 'identifierFormat and forceAuthn',
    options: { identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', forceAuthn: true },
    expectedFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    expectedForceAuthn: true,
  },
  {
    name: 'null identifierFormat',
    options: { identifierFormat: null },
    expectedFormat: undefined,
    expectedForceAuthn: false,
  },
])('resolve login url with options: $name', async ({ options: loginOptions, expectedFormat, expectedForceAuthn }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, ...loginOptions });

  const loginUrl = new URL(await samlServiceProvider.resolveLoginUrl('/'));

  const authnRequest = inflateRawSync(
    Buffer.from(loginUrl.searchParams.get('SAMLRequest') as string, 'base64'),
  ).toString();

  // a null identifierFormat omits the Format of the NameIDPolicy (the identity provider chooses)
  expect(authnRequest).toContain(
    `<samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AllowCreate="true"${
      expectedFormat !== undefined ? ` Format="${expectedFormat}"` : ''
    }/>`,
  );

  if (expectedForceAuthn) {
    expect(authnRequest).toContain('ForceAuthn="true"');
  } else {
    expect(authnRequest).not.toContain('ForceAuthn');
  }

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test.each<{ name: string; comparison: 'exact' | 'minimum' | 'maximum' | 'better' | undefined; expected: string }>([
  { name: 'default', comparison: undefined, expected: 'exact' },
  { name: 'minimum', comparison: 'minimum', expected: 'minimum' },
])('resolve login url with authnContext: $name', async ({ comparison, expected }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    authnContext: {
      classRefs: [
        'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos',
        'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
      ],
      ...(comparison !== undefined ? { comparison } : {}),
    },
  });

  const loginUrl = new URL(await samlServiceProvider.resolveLoginUrl('/'));

  const authnRequest = inflateRawSync(
    Buffer.from(loginUrl.searchParams.get('SAMLRequest') as string, 'base64'),
  ).toString();

  expect(authnRequest).toContain(
    `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="${expected}"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos</saml:AuthnContextClassRef><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`,
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test.each<{ name: string; signatureAlgorithm: 'sha256' | 'sha512' | undefined; expectedSigAlg: string }>([
  {
    name: 'default',
    signatureAlgorithm: undefined,
    expectedSigAlg: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  },
  { name: 'sha512', signatureAlgorithm: 'sha512', expectedSigAlg: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' },
])('resolve login url with signed authn request: $name', async ({ signatureAlgorithm, expectedSigAlg }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    privateKey: keyMaterial.privateKey,
    certificate: keyMaterial.certificatePem,
    signatureAlgorithm,
  });

  const loginUrl = new URL(await samlServiceProvider.resolveLoginUrl('/resource'));

  expect(loginUrl.searchParams.get('SigAlg')).toBe(expectedSigAlg);
  expect(loginUrl.searchParams.get('Signature')).not.toBeNull();

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    sessionIndex: '_session-1',
    attributes: { email: ['user@example.com'], roles: ['admin', 'user'] },
  });

  expect(await samlServiceProvider.verifySamlResponse(samlResponse)).toStrictEqual({
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    sessionIndex: '_session-1',
    authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    issuer: idpEntityId,
    attributes: { email: 'user@example.com', roles: ['admin', 'user'] },
  });

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response without session index, authn context and attributes', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, authnContextClassRef: null });

  expect(await samlServiceProvider.verifySamlResponse(samlResponse)).toStrictEqual({
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    issuer: idpEntityId,
    attributes: {},
  });

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with cached saml instance', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // two responses (the same one again would be a replay), verified by the same saml instance
  const samlResponse = createSamlResponse(keyMaterial, responseOptions);
  const otherSamlResponse = createSamlResponse(keyMaterial, responseOptions);

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');
  expect((await samlServiceProvider.verifySamlResponse(otherSamlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with rotated metadata', async () => {
  const rotatedKeyMaterial = loadKeyMaterial('other');

  const rotatedMetadata: IdpMetadata = { ...metadata, signingCertificates: [rotatedKeyMaterial.certificate] };

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(rotatedMetadata) },
    { parameters: [], return: Promise.resolve(rotatedMetadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  expect((await samlServiceProvider.verifySamlResponse(createSamlResponse(keyMaterial, responseOptions))).nameId).toBe(
    'user@example.com',
  );

  // the old key is not accepted anymore
  await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(createSamlResponse(keyMaterial, responseOptions)),
  );

  // the rotated key is
  expect(
    (await samlServiceProvider.verifySamlResponse(createSamlResponse(rotatedKeyMaterial, responseOptions))).nameId,
  ).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with wrong signature key', async () => {
  const otherKeyMaterial = loadKeyMaterial('other');

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const error = await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(createSamlResponse(otherKeyMaterial, responseOptions)),
  );

  expect(error.cause).toBeInstanceOf(Error);

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with unsigned response', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // the assertion is signed, but the response is not: wantAuthnResponseSigned defaults to true
  await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(
      createSamlResponse(keyMaterial, { ...responseOptions, signResponse: false }),
    ),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with unsigned response and disabled wantAuthnResponseSigned', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    wantAuthnResponseSigned: false,
  });

  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, signResponse: false });

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with unsigned assertion', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // the response is signed, but the assertion is not: wantAssertionsSigned defaults to true
  await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(
      createSamlResponse(keyMaterial, { ...responseOptions, signAssertion: false }),
    ),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with unsigned assertion and disabled wantAssertionsSigned', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    wantAssertionsSigned: false,
  });

  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, signAssertion: false });

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with malformed saml response', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse('bm90IHhtbA=='));

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with expired assertion', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    notBefore: new Date(Date.now() - 300_000),
    notOnOrAfter: new Date(Date.now() - 60_000),
  });

  await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with expired assertion within clock tolerance', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, clockTolerance: 60 });

  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    notBefore: new Date(Date.now() - 300_000),
    notOnOrAfter: new Date(Date.now() - 30_000),
  });

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with assertion within maxAssertionAge', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, maxAssertionAge: 300 });

  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    issueInstant: new Date(Date.now() - 120_000),
    notBefore: new Date(Date.now() - 120_000),
  });

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with assertion older than maxAssertionAge', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, maxAssertionAge: 60 });

  // NotOnOrAfter is still in the future, but the assertion was issued too long ago
  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    issueInstant: new Date(Date.now() - 120_000),
    notBefore: new Date(Date.now() - 120_000),
  });

  await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with wrong audience', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    audience: 'https://other-sp.example.com',
  });

  await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with wrong issuer', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // node-saml does not verify the issuer of an authn response itself, the trusted certificate is its only anchor:
  // the additional issuer check protects against an identity provider signing for multiple issuers with one key
  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    idpEntityId: 'https://other-idp.example.com',
  });

  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(error.message).toBe(
    'Issuer mismatch: expected "https://idp.example.com", given "https://other-idp.example.com"',
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with none success status', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    status: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    includeAssertion: false,
  });

  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(error.message).toBe('SAML provider returned Responder error: unspecified');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with non error rejection', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // node-saml is expected to throw errors only, a non error rejection is still reported as an invalid saml response
  const validatePostResponseAsyncSpy = vi
    .spyOn(SAML.prototype, 'validatePostResponseAsync')
    .mockRejectedValueOnce('non error rejection');

  try {
    const error = await expectInvalidSamlResponseError(
      samlServiceProvider.verifySamlResponse(createSamlResponse(keyMaterial, responseOptions)),
    );

    expect(error.message).toBe('non error rejection');
    expect(error.cause).toBe('non error rejection');

    expect(validatePostResponseAsyncSpy).toHaveBeenCalledTimes(1);
  } finally {
    validatePostResponseAsyncSpy.mockRestore();
  }

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with validateInResponseTo "always" and unsolicited response', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    validateInResponseTo: 'always',
  });

  await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(createSamlResponse(keyMaterial, responseOptions)),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with validateInResponseTo "ifPresent"', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    validateInResponseTo: 'ifPresent',
  });

  // a login stores the authn request id
  const loginUrl = new URL(await samlServiceProvider.resolveLoginUrl('/resource'));

  const authnRequest = inflateRawSync(
    Buffer.from(loginUrl.searchParams.get('SAMLRequest') as string, 'base64'),
  ).toString();

  const inResponseTo = /ID="([^"]+)"/.exec(authnRequest)?.[1] as string;

  // a response to the pending authn request is accepted (and the request id gets consumed)
  expect(
    (
      await samlServiceProvider.verifySamlResponse(
        createSamlResponse(keyMaterial, { ...responseOptions, inResponseTo }),
      )
    ).nameId,
  ).toBe('user@example.com');

  // a replayed response is not
  await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(createSamlResponse(keyMaterial, { ...responseOptions, inResponseTo })),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with validateInResponseTo "ifPresent" and rotated metadata', async () => {
  const rotatedKeyMaterial = loadKeyMaterial('other');

  const rotatedMetadata: IdpMetadata = { ...metadata, signingCertificates: [rotatedKeyMaterial.certificate] };

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(rotatedMetadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    validateInResponseTo: 'ifPresent',
  });

  const loginUrl = new URL(await samlServiceProvider.resolveLoginUrl('/resource'));

  const authnRequest = inflateRawSync(
    Buffer.from(loginUrl.searchParams.get('SAMLRequest') as string, 'base64'),
  ).toString();

  const inResponseTo = /ID="([^"]+)"/.exec(authnRequest)?.[1] as string;

  // the metadata got rotated while the login was pending: the pending authn request id survives the rotation
  expect(
    (
      await samlServiceProvider.verifySamlResponse(
        createSamlResponse(rotatedKeyMaterial, { ...responseOptions, inResponseTo }),
      )
    ).nameId,
  ).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with decryption key and unencrypted assertion', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    decryptionKey: keyMaterial.privateKey,
  });

  const samlResponse = createSamlResponse(keyMaterial, responseOptions);

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with failing idp metadata resolver', async () => {
  const error = new Error('Cannot fetch idp metadata from "https://idp.example.com/metadata": status 500');

  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], error },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  await expect(samlServiceProvider.verifySamlResponse('bm90IHhtbA==')).rejects.toBe(error);

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with replayed assertion', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(metadata) },
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, assertionId: '_assertion-1' });

  expect(await samlServiceProvider.verifySamlResponse(samlResponse)).toMatchObject({ nameId: 'user@example.com' });

  // the very same response again (and a fresh one carrying the same assertion id) is rejected
  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(error.message).toBe('Replayed assertion "_assertion-1"');
  expect(error.cause).toBeUndefined();

  await expectInvalidSamlResponseError(
    samlServiceProvider.verifySamlResponse(
      createSamlResponse(keyMaterial, { ...responseOptions, assertionId: '_assertion-1' }),
    ),
  );

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test.each<{
  name: string;
  responseOptions: Partial<Parameters<typeof createSamlResponse>[1]>;
  clockTolerance: number | undefined;
  expectedExpiresAt: number;
}>([
  {
    name: 'subject confirmation NotOnOrAfter later than conditions NotOnOrAfter',
    responseOptions: {
      subjectConfirmationNotOnOrAfter: new Date('2026-01-01T00:10:00Z'),
      conditionsNotOnOrAfter: new Date('2026-01-01T00:05:00Z'),
    },
    clockTolerance: undefined,
    expectedExpiresAt: Date.parse('2026-01-01T00:10:00Z'),
  },
  {
    name: 'conditions NotOnOrAfter later than subject confirmation NotOnOrAfter, with clock tolerance',
    responseOptions: {
      subjectConfirmationNotOnOrAfter: new Date('2026-01-01T00:05:00Z'),
      conditionsNotOnOrAfter: new Date('2026-01-01T00:10:00Z'),
    },
    clockTolerance: 30,
    expectedExpiresAt: Date.parse('2026-01-01T00:10:30Z'),
  },
])(
  'verify saml response with custom assertion id store: $name',
  async ({ responseOptions: notOnOrAfterOptions, clockTolerance, expectedExpiresAt }) => {
    vi.useFakeTimers({ now: new Date('2026-01-01T00:00:00Z') });

    try {
      const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
        { parameters: [], return: Promise.resolve(metadata) },
        { parameters: [], return: Promise.resolve(metadata) },
      ]);

      const [assertionIdStore, assertionIdStoreMocks] = useObjectMock<SamlAssertionIdStore>([
        { name: 'consume', parameters: ['_assertion-1', expectedExpiresAt], return: Promise.resolve(true) },
        { name: 'consume', parameters: ['_assertion-1', expectedExpiresAt], return: Promise.resolve(false) },
      ]);

      const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
        ...options,
        clockTolerance,
        assertionIdStore,
      });

      const samlResponse = createSamlResponse(keyMaterial, {
        ...responseOptions,
        ...notOnOrAfterOptions,
        assertionId: '_assertion-1',
      });

      expect(await samlServiceProvider.verifySamlResponse(samlResponse)).toMatchObject({ nameId: 'user@example.com' });

      const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

      expect(error.message).toBe('Replayed assertion "_assertion-1"');

      expect(idpMetadataResolverMocks).toHaveLength(0);
      expect(assertionIdStoreMocks).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  },
);

test('verify saml response without NotOnOrAfter', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const [assertionIdStore, assertionIdStoreMocks] = useObjectMock<SamlAssertionIdStore>([]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, { ...options, assertionIdStore });

  // node-saml itself requires both NotOnOrAfter (subject confirmation and conditions): nothing gets remembered
  const samlResponse = createSamlResponse(keyMaterial, {
    ...responseOptions,
    subjectConfirmationNotOnOrAfter: null,
    conditionsNotOnOrAfter: null,
  });

  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(error.message).toBe("Error parsing NotOnOrAfter: 'undefined' is not a valid date");
  expect(error.cause).toBeInstanceOf(Error);

  expect(idpMetadataResolverMocks).toHaveLength(0);
  expect(assertionIdStoreMocks).toHaveLength(0);
});

test.each<{ name: string; responseOptions: Partial<Parameters<typeof createSamlResponse>[1]>; message: string }>([
  {
    name: 'wrong recipient',
    responseOptions: { recipient: 'https://other-sp.example.com/saml/acs' },
    message:
      'Recipient mismatch: expected "https://sp.example.com/saml/acs", given "https://other-sp.example.com/saml/acs"',
  },
  {
    name: 'missing recipient',
    responseOptions: { recipient: null },
    message: 'Recipient mismatch: expected "https://sp.example.com/saml/acs", given "undefined"',
  },
  {
    name: 'wrong destination',
    responseOptions: { destination: 'https://other-sp.example.com/saml/acs' },
    message:
      'Destination mismatch: expected "https://sp.example.com/saml/acs", given "https://other-sp.example.com/saml/acs"',
  },
  {
    name: 'missing destination',
    responseOptions: { destination: null },
    message: 'Destination mismatch: expected "https://sp.example.com/saml/acs", given "null"',
  },
  {
    name: 'wrong destination and disabled wantAuthnResponseSigned',
    responseOptions: { destination: 'https://other-sp.example.com/saml/acs', signResponse: false },
    message:
      'Destination mismatch: expected "https://sp.example.com/saml/acs", given "https://other-sp.example.com/saml/acs"',
  },
])('verify saml response with wrong endpoint: $name', async ({ responseOptions: endpointOptions, message }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const [assertionIdStore, assertionIdStoreMocks] = useObjectMock<SamlAssertionIdStore>([]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    wantAuthnResponseSigned: endpointOptions.signResponse ?? true,
    assertionIdStore,
  });

  // node-saml verifies neither the Destination of the response nor the Recipient of the subject confirmation: an
  // assertion issued for another assertion consumer service must not be accepted (and nothing gets remembered)
  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, ...endpointOptions });

  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(error.message).toBe(message);
  expect(error.cause).toBeUndefined();

  expect(idpMetadataResolverMocks).toHaveLength(0);
  expect(assertionIdStoreMocks).toHaveLength(0);
});

test('verify saml response with missing destination and disabled wantAuthnResponseSigned', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    wantAuthnResponseSigned: false,
  });

  // only a signed response must carry the Destination (profiles 4.1.4.5), an unsigned one does not protect it anyway
  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, destination: null, signResponse: false });

  expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with encrypted assertion and without decryption key', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // a configuration problem (the identity provider encrypts, the service provider cannot decrypt), not an invalid saml
  // response: an internal failure instead of a 403
  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, encryptAssertion: true });

  const error: unknown = await samlServiceProvider.verifySamlResponse(samlResponse).then(
    () => undefined,
    (e: unknown) => e,
  );

  expect(error).toBeInstanceOf(Error);
  expect(error).not.toBeInstanceOf(InvalidSamlResponseError);
  expect((error as Error).message).toBe('Cannot verify the saml response: encrypted assertion without decryptionKey');
  expect(((error as Error).cause as Error).message).toBe('No decryption key for encrypted SAML response');

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('verify saml response with undecryptable assertion and decryption key', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    decryptionKey: keyMaterial.privateKey,
  });

  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, encryptAssertion: true });

  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

  expect(error.cause).toBeInstanceOf(Error);

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test.each<{
  name: string;
  authnContext: SamlServiceProviderOptions['authnContext'];
  authnContextClassRef: string | null;
  message?: string;
}>([
  {
    name: 'exact with a requested class',
    authnContext: {
      classRefs: [
        'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos',
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      ],
    },
    authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  },
  {
    name: 'minimum with another class',
    authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'], comparison: 'minimum' },
    authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  },
  {
    name: 'exact with another class',
    authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'], comparison: 'exact' },
    authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    message:
      'Authentication context mismatch: expected one of "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos", given "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"',
  },
  {
    name: 'exact without class',
    authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'] },
    authnContextClassRef: null,
    message:
      'Authentication context mismatch: expected one of "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos", given "undefined"',
  },
])('verify saml response with authnContext: $name', async ({ authnContext, authnContextClassRef, message }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  // a rejected response must not consume its assertion id
  const [assertionIdStore, assertionIdStoreMocks] = useObjectMock<SamlAssertionIdStore>([]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
    ...options,
    authnContext,
    ...(message !== undefined ? { assertionIdStore } : {}),
  });

  // with an exact comparison the identity provider must have authenticated with one of the requested classes
  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, authnContextClassRef });

  if (message === undefined) {
    expect((await samlServiceProvider.verifySamlResponse(samlResponse)).nameId).toBe('user@example.com');
  } else {
    const error = await expectInvalidSamlResponseError(samlServiceProvider.verifySamlResponse(samlResponse));

    expect(error.message).toBe(message);
    expect(error.cause).toBeUndefined();
  }

  expect(idpMetadataResolverMocks).toHaveLength(0);
  expect(assertionIdStoreMocks).toHaveLength(0);
});

test('verify saml response without name id format', async () => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([
    { parameters: [], return: Promise.resolve(metadata) },
  ]);

  const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, options);

  // node-saml only sets the name id format if the NameID carries a Format attribute
  const samlResponse = createSamlResponse(keyMaterial, { ...responseOptions, nameIdFormat: null });

  expect(await samlServiceProvider.verifySamlResponse(samlResponse)).toStrictEqual({
    nameId: 'user@example.com',
    authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    issuer: idpEntityId,
    attributes: {},
  });

  expect(idpMetadataResolverMocks).toHaveLength(0);
});
