import { createHash } from 'node:crypto';
import { EncryptJWT } from 'jose';
import { expect, test, vi } from 'vitest';
import { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { SamlIdentity } from '../../src/service-provider';
import { createSamlSession } from '../../src/session';

const secret = 'secret-secret-secret-secret-secret-secret';

const identity: SamlIdentity = {
  nameId: 'user@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  sessionIndex: '_session-1',
  issuer: 'https://idp.example.com',
  attributes: { email: 'user@example.com', roles: ['admin', 'user'] },
};

test('create session with invalid secret: too short', () => {
  expect(() => createSamlSession({ secret: 'too-short' })).toThrow(
    'Invalid secret: must be a string with at least 32 characters',
  );
});

test('create session with invalid secret: none string', () => {
  expect(() => createSamlSession({ secret: 42 as unknown as string })).toThrow(
    'Invalid secret: must be a string with at least 32 characters',
  );
});

test('create session with invalid maxAge', () => {
  expect(() => createSamlSession({ secret, maxAge: -1 })).toThrow(
    'Invalid maxAge -1: must be a non-negative number of seconds',
  );
});

test.each<{ name: string; cookieName: string }>([
  { name: 'whitespace', cookieName: 'saml session' },
  { name: 'semicolon', cookieName: 'saml;session' },
  { name: 'equals sign', cookieName: 'saml=session' },
  { name: 'empty', cookieName: '' },
])('create session with invalid cookieName: $name', ({ cookieName }) => {
  expect(() => createSamlSession({ secret, cookieName })).toThrow(
    `Invalid cookieName "${cookieName}": must be a rfc 6265 token`,
  );
});

test.each<{ name: string; path: string }>([
  { name: 'relative', path: 'app' },
  { name: 'whitespace', path: '/some path' },
  { name: 'semicolon', path: '/app;path' },
  { name: 'control character', path: '/app\u0000path' },
  { name: 'non ascii', path: '/äpp' },
])('create session with invalid path: $name', ({ path }) => {
  expect(() => createSamlSession({ secret, path })).toThrow(
    `Invalid path "${path}": must start with "/" and be a rfc 6265 path-value`,
  );
});

test('create session with invalid sameSite', () => {
  expect(() => createSamlSession({ secret, sameSite: 'lax' as 'Lax' })).toThrow(
    'Invalid sameSite "lax": must be one of "Lax", "Strict", "None"',
  );
});

test('create session with sameSite "None" without secure', () => {
  expect(() => createSamlSession({ secret, sameSite: 'None', secure: false })).toThrow(
    'Invalid sameSite "None": requires secure',
  );
});

test('create cookie and resolve identity', async () => {
  const samlSession = createSamlSession({ secret });

  const cookie = await samlSession.createCookie(identity);

  expect(cookie).toMatch(
    /^saml-session=[\w-]+\.\.[\w-]+\.[\w-]+\.[\w-]+; Path=\/; HttpOnly; SameSite=Lax; Secure; Max-Age=3600$/,
  );

  const request = new ServerRequest('https://sp.example.com/resource', {
    headers: { cookie: `key=value; ${cookie.split(';')[0]}; other-key=other-value` },
  });

  expect(await samlSession.resolveIdentity(request)).toEqual(identity);
});

test('create cookie with options', async () => {
  const samlSession = createSamlSession({
    secret,
    maxAge: 60,
    cookieName: 'my-session',
    path: '/app',
    secure: false,
    sameSite: 'Strict',
  });

  const cookie = await samlSession.createCookie(identity);

  expect(cookie).toMatch(/^my-session=[\w-.]+; Path=\/app; HttpOnly; SameSite=Strict; Max-Age=60$/);

  const request = new ServerRequest('https://sp.example.com/resource', {
    headers: { cookie: cookie.split(';')[0] },
  });

  expect(await samlSession.resolveIdentity(request)).toEqual(identity);
});

test('create removal cookie', () => {
  const samlSession = createSamlSession({ secret });

  expect(samlSession.createRemovalCookie()).toBe('saml-session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0');
});

test('resolve identity without cookie header', async () => {
  const samlSession = createSamlSession({ secret });

  const request = new ServerRequest('https://sp.example.com/resource');

  expect(await samlSession.resolveIdentity(request)).toBeUndefined();
});

test('resolve identity without session cookie', async () => {
  const samlSession = createSamlSession({ secret });

  const request = new ServerRequest('https://sp.example.com/resource', {
    headers: { cookie: 'key=value; prefixed-saml-session=some-value' },
  });

  expect(await samlSession.resolveIdentity(request)).toBeUndefined();
});

test('resolve identity with invalid session cookie', async () => {
  const samlSession = createSamlSession({ secret });

  const request = new ServerRequest('https://sp.example.com/resource', {
    headers: { cookie: 'saml-session=invalid-value' },
  });

  expect(await samlSession.resolveIdentity(request)).toBeUndefined();
});

test('resolve identity with session cookie encrypted with another secret', async () => {
  const samlSession = createSamlSession({ secret });
  const otherSamlSession = createSamlSession({ secret: 'other-secret-other-secret-other-secret' });

  const cookie = await otherSamlSession.createCookie(identity);

  const request = new ServerRequest('https://sp.example.com/resource', {
    headers: { cookie: cookie.split(';')[0] as string },
  });

  expect(await samlSession.resolveIdentity(request)).toBeUndefined();
});

test('resolve identity with expired session cookie', async () => {
  vi.useFakeTimers();

  try {
    // a whole second: the expiration is measured in epoch seconds
    vi.setSystemTime(new Date('2026-08-20T12:00:00.000Z'));

    const samlSession = createSamlSession({ secret, maxAge: 10 });

    const cookie = await samlSession.createCookie(identity);

    const request = new ServerRequest('https://sp.example.com/resource', {
      headers: { cookie: cookie.split(';')[0] as string },
    });

    vi.advanceTimersByTime(9999);

    expect(await samlSession.resolveIdentity(request)).toEqual(identity);

    vi.advanceTimersByTime(1);

    expect(await samlSession.resolveIdentity(request)).toBeUndefined();
  } finally {
    vi.useRealTimers();
  }
});

test('resolve identity with none object identity', async () => {
  const samlSession = createSamlSession({ secret });

  const jwt = await new EncryptJWT({ identity: 'not-an-object' })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .encrypt(createHash('sha256').update(secret).digest());

  const request = new ServerRequest('https://sp.example.com/resource', {
    headers: { cookie: `saml-session=${jwt}` },
  });

  expect(await samlSession.resolveIdentity(request)).toBeUndefined();
});
