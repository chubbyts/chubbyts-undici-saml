import type * as jose from 'jose';
import { jwtDecrypt } from 'jose';
import { expect, test, vi } from 'vitest';
import { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { createSamlSession } from '../../src/session';

vi.mock('jose', async (importOriginal) => {
  const original = await importOriginal<typeof jose>();

  return { ...original, jwtDecrypt: vi.fn(original.jwtDecrypt) };
});

const secret = 'secret-secret-secret-secret-secret-secret';

test.each<{ name: string; headers: Record<string, string> }>([
  { name: 'without cookie header', headers: {} },
  { name: 'without session cookie', headers: { cookie: 'other=value' } },
  { name: 'with empty session cookie', headers: { cookie: 'saml-session=' } },
])('resolve identity $name does not try to decrypt', async ({ headers }) => {
  const samlSession = createSamlSession({ secret });

  expect(await samlSession.resolveIdentity(new ServerRequest('https://sp.example.com/', { headers }))).toBeUndefined();

  expect(vi.mocked(jwtDecrypt)).not.toHaveBeenCalled();
});
