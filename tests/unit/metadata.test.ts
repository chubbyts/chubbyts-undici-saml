import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type { IdpMetadata } from '../../src/metadata';
import { createIdpMetadataResolver } from '../../src/metadata';
import { IdpMetadataError } from '../../src/error';
import { createIdpMetadataXml } from '../helper';

const metadataUrl = 'https://idp.example.com/metadata';
const entityId = 'https://idp.example.com';
const singleSignOnServiceLocation = 'https://idp.example.com/sso';

const metadataXml = createIdpMetadataXml({
  entityId,
  certificates: ['Q2VydDE='],
  singleSignOnServiceLocation,
});

const metadata: IdpMetadata = {
  entityId,
  singleSignOnServiceUrl: singleSignOnServiceLocation,
  signingCertificates: ['Q2VydDE='],
};

const createFetchMock = (
  expectedUrl: string,
  response: Response | (() => Promise<Response>),
): { callback: typeof globalThis.fetch } => ({
  callback: async (input, init) => {
    expect(String(input)).toBe(expectedUrl);
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(init?.redirect).toBe('manual');

    return typeof response === 'function' ? response() : response;
  },
});

// let a background refresh (stale-while-revalidate) settle: microtasks only, works with fake timers too
const flush = async (): Promise<void> => {
  await Array.from({ length: 20 }).reduce<Promise<void>>((promise) => promise.then(() => undefined), Promise.resolve());
};

const expectIdpMetadataError = async (promise: Promise<unknown>, message: string): Promise<unknown> => {
  const error: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );

  expect(error).toBeInstanceOf(IdpMetadataError);
  expect((error as IdpMetadataError).name).toBe('IdpMetadataError');
  expect((error as IdpMetadataError).message).toBe(message);

  return (error as IdpMetadataError).cause;
};

test.each<{ name: string; metadataUrl: string }>([
  { name: 'relative', metadataUrl: 'idp.example.com/metadata' },
  { name: 'not a url', metadataUrl: 'not a url' },
  { name: 'non http scheme', metadataUrl: 'ftp://idp.example.com/metadata' },
  { name: 'embedded credentials', metadataUrl: 'https://user:pass@idp.example.com/metadata' },
])('create resolver with invalid metadataUrl: $name', ({ metadataUrl: invalidMetadataUrl }) => {
  expect(() => createIdpMetadataResolver(invalidMetadataUrl)).toThrow(
    `Invalid metadataUrl "${invalidMetadataUrl}": must be an absolute http(s) url`,
  );
});

test.each<{ name: string; options: Record<string, number>; message: string }>([
  { name: 'maxAge', options: { maxAge: -1 }, message: 'Invalid maxAge -1: must be a non-negative number of seconds' },
  {
    name: 'timeout',
    options: { timeout: -0.5 },
    message: 'Invalid timeout -0.5: must be a non-negative number of seconds',
  },
  {
    name: 'cooldown',
    options: { cooldown: Number.NaN },
    message: 'Invalid cooldown NaN: must be a non-negative number of seconds',
  },
  { name: 'maxSize', options: { maxSize: -1 }, message: 'Invalid maxSize -1: must be a non-negative number of bytes' },
])('create resolver with invalid option: $name', ({ options, message }) => {
  expect(() => createIdpMetadataResolver(metadataUrl, options)).toThrow(message);
});

test('resolve metadata exceeding maxSize', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, maxSize: 100 });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Cannot fetch idp metadata from "https://idp.example.com/metadata": exceeds 100 bytes',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata without body', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(null)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Cannot fetch idp metadata from "https://idp.example.com/metadata": invalid xml',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  expect(await idpMetadataResolver()).toEqual(metadata);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with default fetch', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  vi.stubGlobal('fetch', fetch);

  try {
    const idpMetadataResolver = createIdpMetadataResolver(metadataUrl);

    expect(await idpMetadataResolver()).toEqual(metadata);
  } finally {
    vi.unstubAllGlobals();
  }

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with matching entity id', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, entityId });

  expect(await idpMetadataResolver()).toEqual(metadata);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with entity id mismatch', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, {
    fetch,
    entityId: 'https://other-idp.example.com',
  });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Entity id mismatch: expected "https://other-idp.example.com", given "https://idp.example.com"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with multiple key descriptors', async () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>
    Q2Vy
    dDE=
  </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Q2VydDI=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Q2VydDM=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleSignOnServiceLocation}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  // the whitespace within the first certificate is stripped, the encryption certificate and the empty one are ignored
  expect(await idpMetadataResolver()).toEqual({ ...metadata, signingCertificates: ['Q2VydDE=', 'Q2VydDI='] });

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with expiring cache', async () => {
  vi.useFakeTimers();

  try {
    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      createFetchMock(metadataUrl, new Response(metadataXml)),
      createFetchMock(metadataUrl, new Response(metadataXml)),
    ]);

    const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, maxAge: 10 });

    expect(await idpMetadataResolver()).toEqual(metadata);

    vi.advanceTimersByTime(9999);

    expect(await idpMetadataResolver()).toEqual(metadata);
    expect(fetchMocks).toHaveLength(1);

    vi.advanceTimersByTime(1);

    // expired: served stale right away, refreshed in the background
    expect(await idpMetadataResolver()).toEqual(metadata);
    await flush();
    expect(fetchMocks).toHaveLength(0);
  } finally {
    vi.useRealTimers();
  }
});

test('resolve metadata with expired cache: stale while revalidate', async () => {
  vi.useFakeTimers();

  try {
    const rotatedMetadataXml = createIdpMetadataXml({
      entityId,
      certificates: ['Q2VydDI='],
      singleSignOnServiceLocation,
    });

    const { promise: released, resolve: release } = Promise.withResolvers<undefined>();

    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      createFetchMock(metadataUrl, new Response(metadataXml)),
      createFetchMock(metadataUrl, async () => {
        await released;

        return new Response(rotatedMetadataXml);
      }),
    ]);

    const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, maxAge: 10 });

    const resolvedMetadata = await idpMetadataResolver();

    expect(resolvedMetadata).toEqual(metadata);

    vi.advanceTimersByTime(10000);

    // expired cache: the stale metadata is served without waiting for the pending refresh
    expect(await idpMetadataResolver()).toBe(resolvedMetadata);
    expect(await idpMetadataResolver()).toBe(resolvedMetadata);
    expect(fetchMocks).toHaveLength(0);

    release(undefined);
    await flush();

    // refresh done: the rotated metadata replaces the stale one
    expect(await idpMetadataResolver()).toEqual({ ...metadata, signingCertificates: ['Q2VydDI='] });
  } finally {
    vi.useRealTimers();
  }
});

test('resolve metadata with cache', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  const resolvedMetadata = await idpMetadataResolver();

  expect(resolvedMetadata).toEqual(metadata);
  expect(await idpMetadataResolver()).toBe(resolvedMetadata);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata without cache', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, maxAge: 0 });

  expect(await idpMetadataResolver()).toEqual(metadata);
  expect(await idpMetadataResolver()).toEqual(metadata);
  await flush();

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; response: Response }>([
  // a redirect is not followed (redirect: 'manual'): a https -> http redirect must not bypass the https checks
  { name: 'redirect', response: Response.redirect('https://other-idp.example.com/metadata') },
  { name: 'client error', response: new Response(undefined, { status: 404 }) },
  { name: 'server error', response: new Response(undefined, { status: 500 }) },
])('resolve metadata with failed response: $name', async ({ response }) => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([createFetchMock(metadataUrl, response)]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    `Cannot fetch idp metadata from "https://idp.example.com/metadata": status ${response.status}`,
  );

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; body: string }>([
  { name: 'empty', body: '' },
  { name: 'unclosed element', body: '<md:EntityDescriptor' },
  // a duplicated attribute is a fatal error (the others above are recoverable ones)
  { name: 'duplicated attribute', body: '<md:EntityDescriptor entityID="1" entityID="2"/>' },
  { name: 'not xml', body: 'not xml' },
])('resolve metadata with malformed xml: $name', async ({ body }) => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(body)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  const cause = await expectIdpMetadataError(
    idpMetadataResolver(),
    'Cannot fetch idp metadata from "https://idp.example.com/metadata": invalid xml',
  );

  expect(cause).toBeInstanceOf(Error);

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; body: string }>([
  { name: 'other root element', body: '<other/>' },
  { name: 'other namespace', body: '<EntityDescriptor entityID="https://idp.example.com"/>' },
  {
    name: 'entities descriptor (federation aggregate)',
    body: `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">${metadataXml.replace('<?xml version="1.0" encoding="UTF-8"?>', '')}</md:EntitiesDescriptor>`,
  },
])('resolve metadata with missing entity descriptor: $name', async ({ body }) => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(body)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Missing EntityDescriptor root element within idp metadata from "https://idp.example.com/metadata"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with missing entity id', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(
      metadataUrl,
      new Response('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>'),
    ),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Missing entityID within idp metadata from "https://idp.example.com/metadata"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with missing idp sso descriptor', async () => {
  const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>`;

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Missing IDPSSODescriptor within idp metadata for entity id "https://idp.example.com"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; keyDescriptors: string }>([
  { name: 'without key descriptor', keyDescriptors: '' },
  {
    name: 'with encryption key descriptor only',
    keyDescriptors:
      '<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Q2VydDE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>',
  },
  {
    name: 'with empty signing certificate',
    keyDescriptors:
      '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate> </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>',
  },
])('resolve metadata with missing signing certificate: $name', async ({ keyDescriptors }) => {
  const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyDescriptors}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleSignOnServiceLocation}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Missing signing certificate within idp metadata for entity id "https://idp.example.com"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; singleSignOnServices: string; given: string }>([
  { name: 'missing', singleSignOnServices: '', given: 'undefined' },
  {
    name: 'post binding only',
    singleSignOnServices:
      '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>',
    given: 'undefined',
  },
  {
    name: 'missing location',
    singleSignOnServices: '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>',
    given: 'null',
  },
  {
    name: 'relative location',
    singleSignOnServices:
      '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="/sso"/>',
    given: '/sso',
  },
  {
    name: 'non http location',
    singleSignOnServices:
      '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="mailto:sso@idp.example.com"/>',
    given: 'mailto:sso@idp.example.com',
  },
  {
    name: 'location with embedded credentials',
    singleSignOnServices:
      '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://user:pass@idp.example.com/sso"/>',
    given: 'https://user:pass@idp.example.com/sso',
  },
])('resolve metadata with invalid single sign-on location: $name', async ({ singleSignOnServices, given }) => {
  const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Q2VydDE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>${singleSignOnServices}</md:IDPSSODescriptor></md:EntityDescriptor>`;

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    `Missing or invalid http-redirect single sign-on location "${given}" for entity id "https://idp.example.com"`,
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with single logout location', async () => {
  const xml = createIdpMetadataXml({
    entityId,
    certificates: ['Q2VydDE='],
    singleSignOnServiceLocation,
    singleLogoutServiceLocation: 'https://idp.example.com/slo',
  });

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  expect(await idpMetadataResolver()).toEqual({ ...metadata, singleLogoutServiceUrl: 'https://idp.example.com/slo' });

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with post binding single logout location only', async () => {
  const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Q2VydDE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/slo"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleSignOnServiceLocation}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  expect(await idpMetadataResolver()).toEqual(metadata);

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; singleLogoutServices: string; given: string }>([
  {
    name: 'missing location',
    singleLogoutServices: '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>',
    given: 'null',
  },
  {
    name: 'relative location',
    singleLogoutServices:
      '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="/slo"/>',
    given: '/slo',
  },
])('resolve metadata with invalid single logout location: $name', async ({ singleLogoutServices, given }) => {
  const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Q2VydDE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>${singleLogoutServices}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleSignOnServiceLocation}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(xml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    `Invalid http-redirect single logout location "${given}" for entity id "https://idp.example.com"`,
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with https metadata url and http single logout location', async () => {
  const insecureMetadataXml = createIdpMetadataXml({
    entityId,
    certificates: ['Q2VydDE='],
    singleSignOnServiceLocation,
    singleLogoutServiceLocation: 'http://idp.example.com/slo',
  });

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(insecureMetadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Insecure single logout location "http://idp.example.com/slo" for https metadata url "https://idp.example.com/metadata"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with https metadata url and http single sign-on location', async () => {
  const insecureMetadataXml = createIdpMetadataXml({
    entityId,
    certificates: ['Q2VydDE='],
    singleSignOnServiceLocation: 'http://idp.example.com/sso',
  });

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(insecureMetadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expectIdpMetadataError(
    idpMetadataResolver(),
    'Insecure single sign-on location "http://idp.example.com/sso" for https metadata url "https://idp.example.com/metadata"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with http metadata url and http single sign-on location', async () => {
  const httpMetadataUrl = 'http://idp.example.com/metadata';

  const httpMetadataXml = createIdpMetadataXml({
    entityId,
    certificates: ['Q2VydDE='],
    singleSignOnServiceLocation: 'http://idp.example.com/sso',
    singleLogoutServiceLocation: 'http://idp.example.com/slo',
  });

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(httpMetadataUrl, new Response(httpMetadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(httpMetadataUrl, { fetch });

  expect(await idpMetadataResolver()).toEqual({
    ...metadata,
    singleSignOnServiceUrl: 'http://idp.example.com/sso',
    singleLogoutServiceUrl: 'http://idp.example.com/slo',
  });

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with timeout', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async (_input, init) => {
        const signal = init?.signal as AbortSignal;

        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason as Error));
        });
      },
    },
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, timeout: 0.01 });

  const cause = await expectIdpMetadataError(
    idpMetadataResolver(),
    'Cannot fetch idp metadata from "https://idp.example.com/metadata": timeout after 0.01s',
  );

  expect((cause as Error).name).toBe('TimeoutError');

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with unreachable identity provider', async () => {
  const fetchError = new TypeError('fetch failed');

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, () => Promise.reject(fetchError)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  await expect(idpMetadataResolver()).rejects.toBe(fetchError);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata concurrently', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  const [first, second, third] = await Promise.all([
    idpMetadataResolver(),
    idpMetadataResolver(),
    idpMetadataResolver(),
  ]);

  expect(first).toEqual(metadata);
  expect(second).toBe(first);
  expect(third).toBe(first);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata concurrently with failure', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(undefined, { status: 500 })),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch });

  const results = await Promise.allSettled([idpMetadataResolver(), idpMetadataResolver()]);

  expect(results).toHaveLength(2);

  for (const result of results) {
    expect(result.status).toBe('rejected');
    expect((result as PromiseRejectedResult).reason).toBeInstanceOf(Error);
    expect(((result as PromiseRejectedResult).reason as Error).message).toBe(
      'Cannot fetch idp metadata from "https://idp.example.com/metadata": status 500',
    );
  }

  expect(fetchMocks).toHaveLength(0);
});

test('resolve metadata with failure cooldown', async () => {
  vi.useFakeTimers();

  try {
    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      createFetchMock(metadataUrl, new Response(undefined, { status: 500 })),
      createFetchMock(metadataUrl, new Response(metadataXml)),
    ]);

    const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, cooldown: 10 });

    const firstError: unknown = await idpMetadataResolver().then(
      () => undefined,
      (e: unknown) => e,
    );

    expect(firstError).toBeInstanceOf(Error);
    expect((firstError as Error).message).toBe(
      'Cannot fetch idp metadata from "https://idp.example.com/metadata": status 500',
    );

    vi.advanceTimersByTime(9999);

    // within cooldown: same error, no fetch
    await expect(idpMetadataResolver()).rejects.toBe(firstError);
    expect(fetchMocks).toHaveLength(1);

    vi.advanceTimersByTime(1);

    // after cooldown: fetch again, success clears the failure
    expect(await idpMetadataResolver()).toEqual(metadata);
    expect(await idpMetadataResolver()).toEqual(metadata);
    expect(fetchMocks).toHaveLength(0);
  } finally {
    vi.useRealTimers();
  }
});

test('resolve metadata with expired cache and failed refresh', async () => {
  vi.useFakeTimers();

  try {
    const rotatedMetadataXml = createIdpMetadataXml({
      entityId,
      certificates: ['Q2VydDI='],
      singleSignOnServiceLocation,
    });

    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      createFetchMock(metadataUrl, new Response(metadataXml)),
      createFetchMock(metadataUrl, new Response(undefined, { status: 500 })),
      createFetchMock(metadataUrl, new Response(rotatedMetadataXml)),
    ]);

    const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, maxAge: 10, cooldown: 10 });

    expect(await idpMetadataResolver()).toEqual(metadata);

    vi.advanceTimersByTime(10000);

    // expired cache, failed refresh: serve the stale metadata instead of failing
    expect(await idpMetadataResolver()).toEqual(metadata);
    await flush();
    expect(fetchMocks).toHaveLength(1);

    vi.advanceTimersByTime(9999);

    // within cooldown: still stale, no fetch
    expect(await idpMetadataResolver()).toEqual(metadata);
    expect(fetchMocks).toHaveLength(1);

    vi.advanceTimersByTime(1);

    // after cooldown: fetch again (stale served meanwhile), success replaces the stale metadata
    expect(await idpMetadataResolver()).toEqual(metadata);
    await flush();
    expect(await idpMetadataResolver()).toEqual({ ...metadata, signingCertificates: ['Q2VydDI='] });
    expect(fetchMocks).toHaveLength(0);
  } finally {
    vi.useRealTimers();
  }
});

test('resolve metadata without failure cooldown', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(metadataUrl, new Response(undefined, { status: 500 })),
    createFetchMock(metadataUrl, new Response(metadataXml)),
  ]);

  const idpMetadataResolver = createIdpMetadataResolver(metadataUrl, { fetch, cooldown: 0 });

  await expect(idpMetadataResolver()).rejects.toThrow('status 500');
  expect(await idpMetadataResolver()).toEqual(metadata);

  expect(fetchMocks).toHaveLength(0);
});
