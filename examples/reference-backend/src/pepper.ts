/**
 * Pepper storage and release policy (spec 9.4).
 *
 * The pepper is the provider material: >=32 stable bytes, one per user, released only to a
 * caller who proved possession of a valid host token. envelock never sees the token and never
 * makes this request itself. The integrator does, inside its own `getKeyMaterial` callback.
 *
 * ## Why this file carries more weight than it looks like it should
 *
 * Because we cannot verify freshness of authentication with the host app (spec 2.4), a stolen
 * bearer token can obtain material. The attacker still lacks the device's enclave key, so they
 * land on the recovery path and need the recovery factor - but the rate limiting here is one
 * of the few controls that actually applies to them.
 */

import { randomBytes } from 'node:crypto';

export interface PepperRecord {
  material: Buffer;
  keyId: string;
  createdAt: number;
}

/**
 * Where peppers live.
 *
 * The in-memory implementation below is for the reference server only. In production this is a
 * database, and the peppers belong in a KMS-encrypted column or a secrets manager - a plaintext
 * pepper column is a single-table compromise away from every user's vault.
 */
export interface PepperStore {
  get(sub: string): Promise<PepperRecord | undefined>;
  create(sub: string): Promise<PepperRecord>;
}

/** Pepper length. 32 bytes is envelock's minimum; there is no reason to go lower. */
const PEPPER_BYTES = 32;

export class InMemoryPepperStore implements PepperStore {
  private readonly peppers = new Map<string, PepperRecord>();

  async get(sub: string): Promise<PepperRecord | undefined> {
    return this.peppers.get(sub);
  }

  async create(sub: string): Promise<PepperRecord> {
    const existing = this.peppers.get(sub);
    // Never regenerate. A new pepper means a new `KEK_primary`, which strands the user on the
    // recovery path - or, if they have no recovery factor, destroys their data outright.
    if (existing) return existing;

    const record: PepperRecord = {
      material: randomBytes(PEPPER_BYTES),
      // A date is a reasonable keyId: it is stable, it sorts, and it makes a deliberate
      // rotation visible in logs. envelock rewraps automatically when it changes (spec 8.3).
      keyId: new Date().toISOString().slice(0, 10),
      createdAt: Date.now(),
    };
    this.peppers.set(sub, record);
    return record;
  }
}

// ---------------------------------------------------------------------------------------
// Rate limiting (spec 9.4)
// ---------------------------------------------------------------------------------------

export interface RateLimitPolicy {
  /** Releases allowed inside the window. */
  maxPerWindow: number;
  windowMs: number;
  /**
   * Cool-down applied the first time a subject is seen, treating it as a device migration.
   *
   * Spec 9.4 suggests logging such a request and considering a delay before honouring it. Set
   * to `0` to disable; the reference server leaves it off so the quickstart is not confusing,
   * and says so loudly.
   */
  migrationCooldownMs: number;
}

export const DEFAULT_RATE_LIMIT: RateLimitPolicy = {
  maxPerWindow: 10,
  windowMs: 60 * 60 * 1000,
  migrationCooldownMs: 0,
};

export type ReleaseDecision =
  | { allow: true; migration: boolean }
  | { allow: false; reason: 'rate_limited' | 'migration_cooldown'; retryAfterMs: number };

interface SubjectState {
  releases: number[];
  firstSeenAt: number;
}

export class ReleaseLimiter {
  private readonly state = new Map<string, SubjectState>();
  private readonly policy: RateLimitPolicy;

  // Written out rather than as a TS parameter property: Node's `--experimental-strip-types`
  // runs in strip-only mode and cannot desugar those, so the reference server would not start.
  constructor(policy: RateLimitPolicy = DEFAULT_RATE_LIMIT) {
    this.policy = policy;
  }

  /**
   * Decide whether to release material to this subject.
   *
   * `known` says whether the subject already has a pepper. A request from a subject with no
   * enrollment history is a migration event: log it, and consider a cool-down (spec 9.4).
   */
  check(sub: string, known: boolean, now = Date.now()): ReleaseDecision {
    const entry = this.state.get(sub) ?? { releases: [], firstSeenAt: now };
    entry.releases = entry.releases.filter((t) => now - t < this.policy.windowMs);
    this.state.set(sub, entry);

    const migration = !known;

    if (migration && this.policy.migrationCooldownMs > 0) {
      const elapsed = now - entry.firstSeenAt;
      if (elapsed < this.policy.migrationCooldownMs) {
        return {
          allow: false,
          reason: 'migration_cooldown',
          retryAfterMs: this.policy.migrationCooldownMs - elapsed,
        };
      }
    }

    if (entry.releases.length >= this.policy.maxPerWindow) {
      const oldest = entry.releases[0] ?? now;
      return {
        allow: false,
        reason: 'rate_limited',
        retryAfterMs: this.policy.windowMs - (now - oldest),
      };
    }

    return { allow: true, migration };
  }

  /** Record a release. Call only after material actually left the building. */
  record(sub: string, now = Date.now()): void {
    const entry = this.state.get(sub) ?? { releases: [], firstSeenAt: now };
    entry.releases.push(now);
    this.state.set(sub, entry);
  }
}

// ---------------------------------------------------------------------------------------
// Why there is no unlock proof here (spec 10)
// ---------------------------------------------------------------------------------------
//
// Spec 10 offers an optional reinforcement: after a successful unwrap the client sends
// `HMAC(KEK_primary, serverNonce)`, the backend resets its counter only on a valid proof, and
// material release locks after ~10 unconfirmed fetches. A silent client is then
// indistinguishable from a failed one, so failures cannot be hidden by not reporting them.
//
// This backend deliberately does **not** implement it, and the core exposes no API to produce
// the proof. Three reasons, in order of weight:
//
// 1. The threat it addresses does not exist for envelock's recovery factor. Section 10 says
//    outright that 128-bit recovery codes make the whole section unnecessary, and envelock's
//    primary factor is `HighEntropy([u8; 32])` derived by BIP-85 from the wallet seed. The
//    proof defends a *low-entropy* factor against an attacker who holds both device data and
//    the material, where Argon2id alone buys seconds.
// 2. For the passphrase factor, which is a supported but secondary shape, `ReleaseLimiter`
//    above already caps material acquisition at 10 releases per hour. That is the control
//    doing the work; the proof only sharpens *which* 10.
// 3. The cost is not local. Producing the proof means a new domain string, retaining a derived
//    proof key past unlock, an FFI method that must never leak `KEK_primary` itself, and then
//    manual plumbing through the Swift and Kotlin shims, both React Native modules, and a
//    Pigeon regeneration for Flutter - for a control the spec marks optional.
//
// A verifier with nothing able to produce a proof is worse than no verifier: it reads as a
// working control. Hence the deletion rather than a stub.
//
// To revive it: derive a proof key from `KEK_primary` inside `Vault::unlock` (never export the
// KEK), store it alongside the DEK in `Inner`, expose `unlock_proof(nonce) -> Vec<u8>`, and
// compare here with `crypto.timingSafeEqual` after a length check.
