/**
 * Remembers the ids of consumed bearer assertions: the web browser sso profile (4.1.4.5) requires a service provider
 * to reject an assertion it has already accepted, for as long as the assertion could still be valid. `consume` reports
 * `true` for a first use and `false` for a replay, and keeps the id until `expiresAt` (milliseconds since the epoch).
 */
export type SamlAssertionIdStore = {
  consume: (id: string, expiresAt: number) => Promise<boolean>;
};

/**
 * The default store: in memory, so the ids do not survive a restart and are not shared between multiple instances (a
 * replay against another instance is not detected). Use a shared store (database, redis, ...) for a multi instance
 * deployment.
 */
export const createInMemorySamlAssertionIdStore = (): SamlAssertionIdStore => {
  const expiries = new Map<string, number>();

  const consume = async (id: string, expiresAt: number): Promise<boolean> => {
    const now = Date.now();

    // an expired assertion is rejected by its own NotOnOrAfter anyway: its id does not need to be remembered
    expiries.forEach((expiry, expiredId) => {
      if (expiry <= now) {
        // oxlint-disable-next-line functional/immutable-data
        expiries.delete(expiredId);
      }
    });

    if (expiries.has(id)) {
      return false;
    }

    // oxlint-disable-next-line functional/immutable-data
    expiries.set(id, expiresAt);

    return true;
  };

  return { consume };
};
