import type { MaterialReason, VaultOptions } from './types';

/**
 * The determinism harness (spec 7.5).
 *
 * Run this in CI and treat it as a prerequisite. A `getKeyMaterial` that returns different bytes
 * on different calls makes the vault permanently unopenable, and the failure surfaces days
 * later, on a device that had been working, looking exactly like data corruption. Catching it
 * here costs one test.
 *
 * ```ts
 * import { assertProviderDeterministic } from '@sharering/react-native-envelock/testing';
 *
 * it('key material is deterministic', async () => {
 *   await assertProviderDeterministic(vaultOptions, { calls: 10 });
 * });
 * ```
 *
 * ## What this cannot check
 *
 * Determinism *across restarts and across devices*, which is where the real bugs live: a value
 * cached in a module-level variable looks perfectly stable inside one process. Run it again in a
 * fresh process and pass `acrossRestarts` with the previous `fingerprint`.
 */
export interface DeterminismOptions {
  /** How many times to call the provider. Default 10. */
  calls?: number;
  /** Reasons to exercise. Material must not vary by reason. */
  reasons?: MaterialReason[];
  /**
   * A `fingerprint` from a previous run in a *different process*. Supplying it turns this into
   * a cross-restart check, which is the one that catches in-memory caching.
   */
  acrossRestarts?: string;
}

export interface DeterminismReport {
  calls: number;
  keyId: string;
  /**
   * A stable, non-secret digest of the material.
   *
   * Deliberately not the material itself: a CI log is the last place a per-user pepper should
   * end up. It is only ever compared against another fingerprint.
   */
  fingerprint: string;
}

export async function assertProviderDeterministic(
  options: Pick<VaultOptions, 'getKeyMaterial' | 'providerId'>,
  opts: DeterminismOptions = {},
): Promise<DeterminismReport> {
  const calls = opts.calls ?? 10;
  const reasons: MaterialReason[] = opts.reasons ?? ['enroll', 'unlock', 'rotate'];

  let first: { material: Uint8Array; keyId: string } | undefined;

  for (let i = 0; i < calls; i++) {
    const reason = reasons[i % reasons.length]!;
    const result = await options.getKeyMaterial({
      reason,
      nonce: randomBytes(32),
      deadlineMs: 30_000,
    });

    if (result.material.length < 32) {
      throw new Error(
        `getKeyMaterial returned ${result.material.length} bytes; at least 32 are required.`,
      );
    }
    if (result.material.every((b) => b === 0)) {
      throw new Error(
        'getKeyMaterial returned all zeros - an uninitialised buffer, not a secret.',
      );
    }
    if (result.material.every((b) => b === result.material[0])) {
      throw new Error('getKeyMaterial returned a constant byte - this is not a secret.');
    }

    if (!first) {
      first = { material: result.material, keyId: result.keyId };
      continue;
    }

    if (result.keyId !== first.keyId) {
      throw new Error(
        `getKeyMaterial returned keyId "${result.keyId}" on call ${i + 1} but ` +
          `"${first.keyId}" on call 1. A keyId changes only on deliberate rotation; ` +
          'varying it per call triggers an endless rewrap loop.',
      );
    }

    if (!equal(result.material, first.material)) {
      throw new Error(
        `getKeyMaterial returned different bytes on call ${i + 1} (reason "${reason}") than ` +
          'on call 1. It must be byte-identical every time.\n\n' +
          'The usual causes: deriving from a bearer token (tokens rotate), including a ' +
          'timestamp, request id or nonce, or fingerprinting mutable device properties.',
      );
    }
  }

  if (!first) throw new Error('assertProviderDeterministic needs calls >= 1');

  const fingerprint = await digest(first.material, options.providerId);

  if (opts.acrossRestarts !== undefined && opts.acrossRestarts !== fingerprint) {
    throw new Error(
      'getKeyMaterial is stable within one process but changed across restarts. ' +
        'That is the signature of a value cached in memory rather than fetched or stored ' +
        'durably - it will brick every vault on the next cold start.',
    );
  }

  return { calls, keyId: first.keyId, fingerprint };
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const g = globalThis as { crypto?: { getRandomValues?(a: Uint8Array): Uint8Array } };
  if (g.crypto?.getRandomValues) return g.crypto.getRandomValues(out);
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

/**
 * A non-reversible digest of the material, salted by `providerId`.
 *
 * FNV-1a rather than SHA-256 so this needs no crypto dependency and runs identically on Hermes,
 * JSC and Node. It is a comparison token, never a security control - its only job is to let two
 * runs say "same" or "different" without printing a pepper into a CI log.
 */
async function digest(material: Uint8Array, providerId: string): Promise<string> {
  let h = 0x811c9dc5;
  // UTF-8 encoded by hand: `TextEncoder` is absent on some Hermes and JSC builds, and this
  // helper has to run wherever the integrator's tests run.
  const salted: number[] = [];
  for (let i = 0; i < providerId.length; i++) {
    const c = providerId.charCodeAt(i);
    if (c < 0x80) salted.push(c);
    else if (c < 0x800) salted.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else salted.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  salted.push(...material);
  for (const byte of salted) {
    h ^= byte;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}
