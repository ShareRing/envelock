import { assertProviderDeterministic } from '../testing';
import type { KeyMaterialResult, MaterialContext } from '../types';

/**
 * Tests for the determinism harness itself.
 *
 * The harness is the main thing keeping `providerMaterialMismatch` out of the issue tracker
 * (spec 7.5), so it has to actually catch the bugs it claims to - and, just as importantly,
 * it must not reject a provider that is behaving correctly.
 */

const good = () => new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) % 256));

function provider(fn: (ctx: MaterialContext) => Partial<KeyMaterialResult>) {
  return {
    providerId: 'acme-v1',
    getKeyMaterial: async (ctx: MaterialContext): Promise<KeyMaterialResult> => ({
      material: good(),
      keyId: 'v1',
      ...fn(ctx),
    }),
  };
}

describe('assertProviderDeterministic', () => {
  it('accepts a deterministic provider', async () => {
    const report = await assertProviderDeterministic(provider(() => ({})), { calls: 10 });
    expect(report.calls).toBe(10);
    expect(report.keyId).toBe('v1');
    expect(report.fingerprint).toMatch(/^[0-9a-f]{8}$/);
  });

  /** The headline bug: material that changes between calls bricks the vault. */
  it('rejects material that varies per call', async () => {
    let n = 0;
    const p = provider(() => {
      const m = good();
      m[0] = n++;
      return { material: m };
    });
    await expect(assertProviderDeterministic(p, { calls: 5 })).rejects.toThrow(
      /different bytes on call/,
    );
  });

  /** Deriving from a bearer token is the classic mistake; it varies by reason in some SDKs. */
  it('rejects material that varies by reason', async () => {
    const p = provider((ctx) => {
      const m = good();
      if (ctx.reason === 'rotate') m[31] = (m[31] ?? 0) ^ 0xff;
      return { material: m };
    });
    await expect(assertProviderDeterministic(p, { calls: 6 })).rejects.toThrow(
      /different bytes on call/,
    );
  });

  it('rejects a keyId that changes per call', async () => {
    let n = 0;
    await expect(
      assertProviderDeterministic(provider(() => ({ keyId: `v${n++}` })), { calls: 3 }),
    ).rejects.toThrow(/keyId/);
  });

  it('rejects material shorter than 32 bytes', async () => {
    await expect(
      assertProviderDeterministic(provider(() => ({ material: new Uint8Array(31) })), { calls: 1 }),
    ).rejects.toThrow(/at least 32/);
  });

  it('rejects an all-zero buffer', async () => {
    await expect(
      assertProviderDeterministic(provider(() => ({ material: new Uint8Array(32) })), { calls: 1 }),
    ).rejects.toThrow(/all zeros/);
  });

  it('rejects a constant byte', async () => {
    await expect(
      assertProviderDeterministic(
        provider(() => ({ material: new Uint8Array(32).fill(0xab) })),
        { calls: 1 },
      ),
    ).rejects.toThrow(/constant byte/);
  });

  /**
   * The fingerprint is compared across runs, so it must be stable for identical input and
   * different for different input - and it must never be the material itself.
   */
  it('produces a stable, non-revealing fingerprint', async () => {
    const a = await assertProviderDeterministic(provider(() => ({})), { calls: 2 });
    const b = await assertProviderDeterministic(provider(() => ({})), { calls: 2 });
    expect(a.fingerprint).toBe(b.fingerprint);

    const other = await assertProviderDeterministic(
      { ...provider(() => ({})), providerId: 'other' },
      { calls: 2 },
    );
    expect(other.fingerprint).not.toBe(a.fingerprint);

    // The material must not be recoverable from, or present in, the fingerprint.
    expect(a.fingerprint.length).toBe(8);
  });

  /** The cross-restart check is the one that catches a value cached in a module variable. */
  it('detects material that changed across restarts', async () => {
    const first = await assertProviderDeterministic(provider(() => ({})), { calls: 2 });

    const changed = provider(() => ({ material: new Uint8Array(32).fill(9).fill(3, 0, 8) }));
    await expect(
      assertProviderDeterministic(changed, { calls: 2, acrossRestarts: first.fingerprint }),
    ).rejects.toThrow(/across restarts/);
  });

  it('passes the cross-restart check when the material really is stable', async () => {
    const first = await assertProviderDeterministic(provider(() => ({})), { calls: 2 });
    await expect(
      assertProviderDeterministic(provider(() => ({})), {
        calls: 2,
        acrossRestarts: first.fingerprint,
      }),
    ).resolves.toBeTruthy();
  });

  /** A fresh nonce every call, so a provider cannot accidentally depend on it. */
  it('supplies a distinct 32-byte nonce on every call', async () => {
    const seen = new Set<string>();
    await assertProviderDeterministic(
      provider((ctx) => {
        expect(ctx.nonce.length).toBe(32);
        seen.add(ctx.nonce.join(','));
        return {};
      }),
      { calls: 5 },
    );
    expect(seen.size).toBe(5);
  });
});
