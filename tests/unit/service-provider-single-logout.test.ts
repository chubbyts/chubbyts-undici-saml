import { expect, test } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type { IdpMetadata, IdpMetadataResolver } from '../../src/metadata';
import type { SamlIdentity, SamlServiceProviderOptions } from '../../src/service-provider';
import { createSamlServiceProvider } from '../../src/service-provider';
import { InvalidSamlResponseError } from '../../src/error';
import type { LogoutRequestXmlOptions, RedirectQueryOptions } from '../helper';
import {
  createLogoutRequestXml,
  createLogoutResponseXml,
  createRedirectQuery,
  generateIdpKeyMaterial,
  inflateRedirectMessage,
} from '../helper';

const idpEntityId = 'https://idp.example.com';
const spEntityId = 'https://sp.example.com';
const assertionConsumerServiceUrl = 'https://sp.example.com/saml/acs';
const singleLogoutServiceUrl = 'https://sp.example.com/saml/slo';
const singleSignOnServiceUrl = 'https://idp.example.com/sso';
const idpSingleLogoutServiceUrl = 'https://idp.example.com/slo';

const keyMaterial = await generateIdpKeyMaterial();
const spKeyMaterial = await generateIdpKeyMaterial();

const metadata: IdpMetadata = {
  entityId: idpEntityId,
  singleSignOnServiceUrl,
  singleLogoutServiceUrl: idpSingleLogoutServiceUrl,
  signingCertificates: [keyMaterial.certificate],
};

const options: SamlServiceProviderOptions = {
  entityId: spEntityId,
  assertionConsumerServiceUrl,
  singleLogoutServiceUrl,
  privateKey: spKeyMaterial.privateKey,
  certificate: spKeyMaterial.certificatePem,
};

const identity: SamlIdentity = {
  nameId: 'user@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  sessionIndex: '_session-1',
  issuer: idpEntityId,
  attributes: {},
};

const createLogoutRequestQuery = (
  logoutRequestOptions: Partial<LogoutRequestXmlOptions> = {},
  queryOptions: RedirectQueryOptions = {},
): string => {
  return createRedirectQuery(
    keyMaterial,
    'SAMLRequest',
    createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl, ...logoutRequestOptions }),
    queryOptions,
  );
};

// resolves is the number of expected idp metadata resolver calls (one per service provider operation)
const createServiceProvider = (
  metadataOverride: IdpMetadata = metadata,
  optionsOverride: SamlServiceProviderOptions = options,
  resolves = 1,
): [ReturnType<typeof createSamlServiceProvider>, () => void] => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>(
    Array.from({ length: resolves }, () => ({ parameters: [], return: Promise.resolve(metadataOverride) })),
  );

  return [
    createSamlServiceProvider(idpMetadataResolver, optionsOverride),
    () => expect(idpMetadataResolverMocks).toHaveLength(0),
  ];
};

const expectInvalidSamlResponseError = async (
  promise: Promise<unknown>,
  message: string,
): Promise<InvalidSamlResponseError> => {
  const error: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );

  expect(error).toBeInstanceOf(InvalidSamlResponseError);
  expect((error as InvalidSamlResponseError).name).toBe('InvalidSamlResponseError');
  expect((error as InvalidSamlResponseError).message).toBe(message);

  return error as InvalidSamlResponseError;
};

test.each<{ name: string; options: SamlServiceProviderOptions; message: string }>([
  {
    name: 'relative singleLogoutServiceUrl',
    options: { ...options, singleLogoutServiceUrl: '/saml/slo' },
    message: 'Invalid singleLogoutServiceUrl "/saml/slo": must be an absolute http(s) url',
  },
  {
    name: 'singleLogoutServiceUrl without privateKey',
    options: { ...options, privateKey: undefined, certificate: undefined },
    message: 'Invalid singleLogoutServiceUrl: requires privateKey (logout messages must be signed)',
  },
])('create service provider with invalid options: $name', ({ options: invalidOptions, message }) => {
  const [idpMetadataResolver, idpMetadataResolverMocks] = useFunctionMock<IdpMetadataResolver>([]);

  expect(() => createSamlServiceProvider(idpMetadataResolver, invalidOptions)).toThrow(new Error(message));

  expect(idpMetadataResolverMocks).toHaveLength(0);
});

test('resolve logout url', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const logoutUrl = new URL((await samlServiceProvider.resolveLogoutUrl(identity, '/resource?key=value')) as string);

  expect(`${logoutUrl.origin}${logoutUrl.pathname}`).toBe(idpSingleLogoutServiceUrl);
  expect(logoutUrl.searchParams.get('RelayState')).toBe('/resource?key=value');
  expect(logoutUrl.searchParams.get('SigAlg')).toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  expect(logoutUrl.searchParams.get('Signature')).not.toBeNull();

  const logoutRequest = inflateRedirectMessage(logoutUrl, 'SAMLRequest');

  expect(logoutRequest).toContain('<samlp:LogoutRequest');
  expect(logoutRequest).toContain(`Destination="${idpSingleLogoutServiceUrl}"`);
  expect(logoutRequest).toContain(`>${spEntityId}</saml:Issuer>`);
  expect(logoutRequest).toContain(
    '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>',
  );
  expect(logoutRequest).toContain('>_session-1</saml2p:SessionIndex>');

  verifyMocks();
});

test('resolve logout url without session index', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const { sessionIndex: _, ...identityWithoutSessionIndex } = identity;

  const logoutUrl = new URL((await samlServiceProvider.resolveLogoutUrl(identityWithoutSessionIndex, '/')) as string);

  expect(inflateRedirectMessage(logoutUrl, 'SAMLRequest')).not.toContain('SessionIndex');

  verifyMocks();
});

test('resolve logout url without service provider single logout service url', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider(metadata, {
    entityId: spEntityId,
    assertionConsumerServiceUrl,
  });

  expect(await samlServiceProvider.resolveLogoutUrl(identity, '/')).toBeUndefined();

  verifyMocks();
});

test('resolve logout url without identity provider single logout service url', async () => {
  const { singleLogoutServiceUrl: _, ...metadataWithoutSingleLogout } = metadata;

  const [samlServiceProvider, verifyMocks] = createServiceProvider(metadataWithoutSingleLogout);

  expect(await samlServiceProvider.resolveLogoutUrl(identity, '/')).toBeUndefined();

  verifyMocks();
});

test('verify logout request', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const query = createLogoutRequestQuery({ sessionIndex: '_session-1' }, { relayState: 'idp-relay-state' });

  expect(await samlServiceProvider.verifyLogoutRequest(query)).toStrictEqual({
    id: '_logout-request-1',
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    sessionIndex: '_session-1',
  });

  verifyMocks();
});

test('verify logout request without name id format, session index and relay state', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const query = createLogoutRequestQuery({ nameIdFormat: null });

  expect(await samlServiceProvider.verifyLogoutRequest(query)).toStrictEqual({
    id: '_logout-request-1',
    nameId: 'user@example.com',
  });

  verifyMocks();
});

test('verify logout request with sha512 signature', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const query = createLogoutRequestQuery(
    {},
    { sigAlg: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', hashAlgorithm: 'RSA-SHA512' },
  );

  expect(await samlServiceProvider.verifyLogoutRequest(query)).toStrictEqual({
    id: '_logout-request-1',
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  });

  verifyMocks();
});

test('verify logout request with expired request within clock tolerance', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider(metadata, { ...options, clockTolerance: 60 });

  const query = createLogoutRequestQuery({ notOnOrAfter: new Date(Date.now() - 30_000) });

  expect(await samlServiceProvider.verifyLogoutRequest(query)).toStrictEqual({
    id: '_logout-request-1',
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  });

  verifyMocks();
});

test('verify logout request without service provider single logout service url', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider(
    metadata,
    { entityId: spEntityId, assertionConsumerServiceUrl },
    0,
  );

  await expect(samlServiceProvider.verifyLogoutRequest(createLogoutRequestQuery())).rejects.toThrow(
    new Error('Single logout is not configured: missing singleLogoutServiceUrl'),
  );

  verifyMocks();
});

test('verify logout request without identity provider single logout service url', async () => {
  const { singleLogoutServiceUrl: _, ...metadataWithoutSingleLogout } = metadata;

  const [samlServiceProvider, verifyMocks] = createServiceProvider(metadataWithoutSingleLogout);

  await expectInvalidSamlResponseError(
    samlServiceProvider.verifyLogoutRequest(createLogoutRequestQuery()),
    'Unexpected logout request: no single logout location within the idp metadata for entity id "https://idp.example.com"',
  );

  verifyMocks();
});

test.each<{ name: string; query: string; message: string; cause?: boolean }>([
  { name: 'missing SAMLRequest', query: 'RelayState=state', message: 'Missing "SAMLRequest" parameter' },
  {
    name: 'unsigned',
    query: createLogoutRequestQuery({}, { sign: false }),
    message: 'Missing "SigAlg" or "Signature" parameter: the logout message must be signed',
  },
  {
    name: 'missing signature',
    query: `${createLogoutRequestQuery({}, { sign: false })}&SigAlg=${encodeURIComponent(
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    )}`,
    message: 'Missing "SigAlg" or "Signature" parameter: the logout message must be signed',
  },
  {
    name: 'sha1 signature',
    query: createLogoutRequestQuery(
      {},
      { sigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', hashAlgorithm: 'RSA-SHA1' },
    ),
    message: 'Unsupported signature algorithm "http://www.w3.org/2000/09/xmldsig#rsa-sha1"',
  },
  {
    name: 'not deflated',
    query: createLogoutRequestQuery({}, { deflate: false }),
    message: 'Cannot inflate "SAMLRequest" parameter',
    cause: true,
  },
  {
    name: 'inflating beyond the size limit',
    query: createLogoutRequestQuery({ nameId: 'x'.repeat(70_000) }),
    message: 'Cannot inflate "SAMLRequest" parameter',
    cause: true,
  },
  {
    name: 'invalid xml',
    query: createRedirectQuery(keyMaterial, 'SAMLRequest', '<samlp:LogoutRequest'),
    message: 'Cannot parse "SAMLRequest" parameter: invalid xml',
    cause: true,
  },
  {
    name: 'logout response instead of logout request',
    query: createRedirectQuery(
      keyMaterial,
      'SAMLRequest',
      createLogoutResponseXml({ idpEntityId, destination: singleLogoutServiceUrl }),
    ),
    message: 'Missing LogoutRequest root element within "SAMLRequest" parameter',
  },
  {
    name: 'wrong namespace',
    query: createRedirectQuery(keyMaterial, 'SAMLRequest', '<LogoutRequest xmlns="urn:example" />'),
    message: 'Missing LogoutRequest root element within "SAMLRequest" parameter',
  },
  {
    name: 'destination mismatch',
    query: createLogoutRequestQuery({ destination: 'https://other-sp.example.com/saml/slo' }),
    message:
      'Destination mismatch: expected "https://sp.example.com/saml/slo", given "https://other-sp.example.com/saml/slo"',
  },
  {
    name: 'missing destination',
    query: createRedirectQuery(
      keyMaterial,
      'SAMLRequest',
      createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl }).replace(
        ` Destination="${singleLogoutServiceUrl}"`,
        '',
      ),
    ),
    message: 'Destination mismatch: expected "https://sp.example.com/saml/slo", given "null"',
  },
  {
    name: 'wrong signature key',
    query: createRedirectQuery(
      spKeyMaterial,
      'SAMLRequest',
      createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl }),
    ),
    message: 'Invalid query signature',
    cause: true,
  },
  {
    name: 'tampered relay state',
    query: createLogoutRequestQuery({}, { relayState: 'state' }).replace('RelayState=state', 'RelayState=other'),
    message: 'Invalid query signature',
    cause: true,
  },
  {
    name: 'wrong issuer',
    query: createLogoutRequestQuery({ idpEntityId: 'https://other-idp.example.com' }),
    message: 'Unknown SAML issuer. Expected: https://idp.example.com Received: https://other-idp.example.com',
    cause: true,
  },
  {
    name: 'expired',
    query: createLogoutRequestQuery({ notOnOrAfter: new Date(Date.now() - 30_000) }),
    message: 'SAML assertion expired: clocks skewed too much',
    cause: true,
  },
])('verify logout request with invalid query: $name', async ({ query, message, cause = false }) => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const error = await expectInvalidSamlResponseError(samlServiceProvider.verifyLogoutRequest(query), message);

  if (cause) {
    expect(error.cause).toBeInstanceOf(Error);
  } else {
    expect(error.cause).toBeUndefined();
  }

  verifyMocks();
});

test('resolve logout response url', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const logoutResponseUrl = new URL(
    await samlServiceProvider.resolveLogoutResponseUrl(
      { id: '_logout-request-1', nameId: 'user@example.com' },
      'idp-relay-state',
      true,
    ),
  );

  expect(`${logoutResponseUrl.origin}${logoutResponseUrl.pathname}`).toBe(idpSingleLogoutServiceUrl);
  expect(logoutResponseUrl.searchParams.get('RelayState')).toBe('idp-relay-state');
  expect(logoutResponseUrl.searchParams.get('SigAlg')).toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  expect(logoutResponseUrl.searchParams.get('Signature')).not.toBeNull();

  const logoutResponse = inflateRedirectMessage(logoutResponseUrl, 'SAMLResponse');

  expect(logoutResponse).toContain('<samlp:LogoutResponse');
  expect(logoutResponse).toContain(`Destination="${idpSingleLogoutServiceUrl}"`);
  expect(logoutResponse).toContain('InResponseTo="_logout-request-1"');
  expect(logoutResponse).toContain(`>${spEntityId}</saml:Issuer>`);
  expect(logoutResponse).toContain('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>');

  verifyMocks();
});

test('resolve logout response url with failure and without relay state', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const logoutResponseUrl = new URL(
    await samlServiceProvider.resolveLogoutResponseUrl(
      { id: '_logout-request-1', nameId: 'user@example.com' },
      undefined,
      false,
    ),
  );

  expect(logoutResponseUrl.searchParams.get('RelayState')).toBeNull();

  const logoutResponse = inflateRedirectMessage(logoutResponseUrl, 'SAMLResponse');

  expect(logoutResponse).toContain('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">');

  verifyMocks();
});

test('verify logout response', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  const query = createRedirectQuery(
    keyMaterial,
    'SAMLResponse',
    createLogoutResponseXml({ idpEntityId, destination: singleLogoutServiceUrl, inResponseTo: '_unknown' }),
    { relayState: '/resource' },
  );

  expect(await samlServiceProvider.verifyLogoutResponse(query)).toBeUndefined();

  verifyMocks();
});

test('verify logout response with validateInResponseTo "always"', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider(
    metadata,
    { ...options, validateInResponseTo: 'always' },
    4,
  );

  const logoutUrl = new URL((await samlServiceProvider.resolveLogoutUrl(identity, '/')) as string);

  const [, logoutRequestId] = /ID="([^"]+)"/.exec(inflateRedirectMessage(logoutUrl, 'SAMLRequest')) as RegExpExecArray;

  const createQuery = (inResponseTo: string | undefined): string =>
    createRedirectQuery(
      keyMaterial,
      'SAMLResponse',
      createLogoutResponseXml({ idpEntityId, destination: singleLogoutServiceUrl, inResponseTo }),
    );

  await expectInvalidSamlResponseError(
    samlServiceProvider.verifyLogoutResponse(createQuery(undefined)),
    'Missing InResponseTo within logout response',
  );

  await expectInvalidSamlResponseError(
    samlServiceProvider.verifyLogoutResponse(createQuery('_unknown')),
    'InResponseTo is not valid',
  );

  expect(await samlServiceProvider.verifyLogoutResponse(createQuery(logoutRequestId))).toBeUndefined();

  verifyMocks();
});

test('verify logout response without service provider single logout service url', async () => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider(
    metadata,
    { entityId: spEntityId, assertionConsumerServiceUrl },
    0,
  );

  await expect(samlServiceProvider.verifyLogoutResponse('SAMLResponse=x')).rejects.toThrow(
    new Error('Single logout is not configured: missing singleLogoutServiceUrl'),
  );

  verifyMocks();
});

test.each<{ name: string; query: string; message: string }>([
  { name: 'missing SAMLResponse', query: 'SAMLRequest=x', message: 'Missing "SAMLResponse" parameter' },
  {
    name: 'logout request instead of logout response',
    query: createRedirectQuery(
      keyMaterial,
      'SAMLResponse',
      createLogoutRequestXml({ idpEntityId, destination: singleLogoutServiceUrl }),
    ),
    message: 'Missing LogoutResponse root element within "SAMLResponse" parameter',
  },
  {
    name: 'destination mismatch',
    query: createRedirectQuery(
      keyMaterial,
      'SAMLResponse',
      createLogoutResponseXml({ idpEntityId, destination: 'https://other-sp.example.com/saml/slo' }),
    ),
    message:
      'Destination mismatch: expected "https://sp.example.com/saml/slo", given "https://other-sp.example.com/saml/slo"',
  },
  {
    name: 'none success status',
    query: createRedirectQuery(
      keyMaterial,
      'SAMLResponse',
      createLogoutResponseXml({
        idpEntityId,
        destination: singleLogoutServiceUrl,
        status: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
      }),
    ),
    message: 'Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester',
  },
  {
    name: 'wrong signature key',
    query: createRedirectQuery(
      spKeyMaterial,
      'SAMLResponse',
      createLogoutResponseXml({ idpEntityId, destination: singleLogoutServiceUrl }),
    ),
    message: 'Invalid query signature',
  },
  {
    name: 'wrong issuer',
    query: createRedirectQuery(
      keyMaterial,
      'SAMLResponse',
      createLogoutResponseXml({ idpEntityId: 'https://other-idp.example.com', destination: singleLogoutServiceUrl }),
    ),
    message: 'Unknown SAML issuer. Expected: https://idp.example.com Received: https://other-idp.example.com',
  },
])('verify logout response with invalid query: $name', async ({ query, message }) => {
  const [samlServiceProvider, verifyMocks] = createServiceProvider();

  await expectInvalidSamlResponseError(samlServiceProvider.verifyLogoutResponse(query), message);

  verifyMocks();
});
