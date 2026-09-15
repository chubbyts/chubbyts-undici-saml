import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { createInMemorySamlAssertionIdStore } from '../../src/assertion-id-store';

beforeEach(() => {
  vi.useFakeTimers({ now: new Date('2026-01-01T00:00:00Z') });
});

afterEach(() => {
  vi.useRealTimers();
});

test('consume', async () => {
  const assertionIdStore = createInMemorySamlAssertionIdStore();

  const expiresAt = Date.now() + 300_000;

  expect(await assertionIdStore.consume('_assertion-1', expiresAt)).toBe(true);
  expect(await assertionIdStore.consume('_assertion-2', expiresAt)).toBe(true);

  // a replay
  expect(await assertionIdStore.consume('_assertion-1', expiresAt)).toBe(false);
  expect(await assertionIdStore.consume('_assertion-2', expiresAt)).toBe(false);

  // the ids are kept until they expire, not until another id is consumed
  vi.advanceTimersByTime(299_999);

  expect(await assertionIdStore.consume('_assertion-1', expiresAt)).toBe(false);

  // an expired id is forgotten (the assertion itself is rejected as expired by then)
  vi.advanceTimersByTime(1);

  expect(await assertionIdStore.consume('_assertion-1', expiresAt + 300_000)).toBe(true);
  expect(await assertionIdStore.consume('_assertion-2', expiresAt + 300_000)).toBe(true);
});
