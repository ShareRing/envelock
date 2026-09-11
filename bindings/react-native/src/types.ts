/**
 * The public types for `@sharering/react-native-envelock`.
 *
 * ## The three secrets - read this before anything else (spec 0)
 *
 * | Term | What it is | Who sees it |
 * |---|---|---|
 * | **App login credential** | Whatever your app logs its user in with, usually verified server-side | Your app only. **Never envelock.** |
 * | **Provider material** | >=32 stable bytes you supply via {@link VaultOptions.getKeyMaterial} | You and your backend |
 * | **Recovery factor** | Opens the vault when the enclave key is gone | envelock only |
 *
 * The recovery factor is **not** your login credential. It is never compared against a stored value; it
 * is KDF input and nothing else. Integrators assume otherwise unless told plainly.
 */

/** Why envelock is asking for key material. */
export type MaterialReason = 'enroll' | 'unlock' | 'rotate';

/** Why envelock is asking for the recovery factor. */
export type RecoveryReason =
  /** New device: the envelope was restored but no enclave key exists (spec 8.4). */
  | 'migrate'
  /** The primary path failed on a device that should have had an enclave key. */
  | 'fallback'
  /** The user is deliberately changing their recovery factor. */
  | 'change';

export interface MaterialContext {
  reason: MaterialReason;
  /**
   * 32 fresh bytes, for challenge-response with your own backend. envelock never inspects any
   * response to this; nothing in the key hierarchy depends on it.
   */
  nonce: Uint8Array;
  /** envelock enforces this itself. A hung callback becomes `Unavailable`, never a spinner. */
  deadlineMs: number;
}

export interface KeyMaterialResult {
  /**
   * At least 32 bytes, and **byte-identical on every call** for a given `keyId`.
   *
   * Valid sources: a server-held per-user pepper, a value stored in envelock at enrollment,
   * WebAuthn PRF output for a fixed salt.
   *
   * Invalid, and they will permanently brick user data: bearer/access/refresh tokens (they
   * rotate); anything containing a timestamp, request id or nonce; device fingerprints
   * assembled from mutable OS properties; anything derived from a login credential, which the user
   * changes at will (spec 7.3).
   */
  material: Uint8Array;
  /** Changes only on deliberate rotation, which triggers an automatic rewrap (spec 8.3). */
  keyId: string;
  /** Default `true`. envelock caches it sealed under the enclave key (spec 7.6). */
  cacheable?: boolean;
  /** Default 30 days. */
  cacheTtlMs?: number;
}

/**
 * The recovery factor.
 *
 * `highEntropy` is the intended shape: 32 uniform bytes, typically a BIP-85 child key derived
 * from the wallet's BIP-39 seed. 128 bits is not guessable, so no attempt limiting applies.
 *
 * `passphrase` is for a user-chosen secret. Argon2id stretches it and the spec 10 backoff
 * ladder engages, up to destroying the vault after repeated failures.
 */
export type RecoveryFactor =
  | { kind: 'highEntropy'; bytes: Uint8Array }
  | { kind: 'passphrase'; value: string };

export type VaultState =
  | { state: 'not_enrolled' }
  | { state: 'locked' }
  | { state: 'unlocked' }
  | { state: 'locked_out'; untilMs: number }
  /** The envelope exists but the enclave key does not - a restored backup on a new device. */
  | { state: 'needs_recovery' };

export type HardwareBacking = 'secureEnclave' | 'strongBox' | 'tee' | 'software';

export interface SecurityInfo {
  /** Reported truthfully. `software` means the spec 2.3 security floor does not hold. */
  hardwareBacking: HardwareBacking;
  providerId: string;
  keyId: string;
  recoveryKind: 'highEntropy' | 'passphrase';
  enrolledAt: number;
  failedAttempts: number;
  lockedUntil: number;
  materialCachedUntil?: number;
}

export type SecurityEvent =
  | { type: 'enrolled'; hardware: HardwareBacking }
  | { type: 'unlocked'; usedCache: boolean }
  | { type: 'recoveryUsed' }
  | { type: 'unlockFailed'; counted: boolean }
  | { type: 'providerKeyRotated'; from: string; to: string }
  | { type: 'materialFetched'; reason: MaterialReason }
  | { type: 'materialCacheEvicted'; reason: string }
  | { type: 'lockedOut'; untilMs: number }
  | { type: 'vaultDestroyed'; reason: string }
  | { type: 'hardwareDowngraded'; to: HardwareBacking };

/**
 * How your callback rejects decides whether a legitimate user is locked out of their own data
 * (spec 7.4).
 *
 * - `cancelled`: user dismissed a prompt. Normal, **not** counted. Render a calm state.
 * - `unavailable`: offline or backend down. Retryable, **not** counted.
 * - `denied`: verification genuinely failed. The **only** code that counts toward lockout.
 * - `misconfigured`: your bug. Surfaced loudly, **not** counted.
 * - `providerMaterialMismatch`: your callback returned different bytes than at enrollment.
 * - `providerKeyRotated`: expected; drive `unlockWithRecovery()` to rewrap.
 * - `materialRejected`: the material failed the enrollment sanity checks.
 * - `corruptData`: stored data is corrupt or was tampered with.
 * - `unexpected`: anything else. Treated as retryable.
 *
 * One code is never something a callback returns: `platformUnsupported`, raised by
 * `Vault.create` on web and desktop, where there is no enclave to gate anything (spec 6.4).
 *
 * Throwing anything that is not a {@link VaultError} is treated as `unavailable`: the safe
 * default is retryable, not punitive, because a flaky network must never march a legitimate
 * user toward lockout.
 */
export type VaultErrorCode =
  | 'cancelled'
  | 'unavailable'
  | 'denied'
  | 'misconfigured'
  | 'providerMaterialMismatch'
  | 'providerKeyRotated'
  | 'materialRejected'
  | 'corruptData'
  | 'unexpected'
  | 'platformUnsupported';

export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'VaultError';
  }

  /** The user dismissed a prompt. Normal behaviour; never counted toward lockout. */
  static cancelled(message?: string) {
    return new VaultError('cancelled', message);
  }

  /** Offline, backend down, or any transient failure. Retryable; never counted. */
  static unavailable(message?: string) {
    return new VaultError('unavailable', message);
  }

  /** Verification genuinely failed. The only code that counts toward lockout. */
  static denied(message?: string) {
    return new VaultError('denied', message);
  }

  /** An integrator bug worth surfacing loudly. Never counted. */
  static misconfigured(message?: string) {
    return new VaultError('misconfigured', message);
  }
}

export interface VaultOptions {
  /**
   * Stable identifier namespaced into derivation.
   *
   * **Changing it invalidates every existing vault.** Pick it once.
   */
  providerId: string;

  /**
   * Supplies the provider material - your half of `KEK_primary`.
   *
   * There is no token parameter here and no endpoint option anywhere in envelock. If fetching
   * material needs a bearer token, obtain and use it inside this function. That keeps "the
   * token is a credential for *fetching* material, never the material itself" a structural
   * property rather than a line in the docs (spec 7.3).
   *
   * **It must be deterministic.** Verify that in CI with `assertProviderDeterministic`.
   */
  getKeyMaterial(ctx: MaterialContext): Promise<KeyMaterialResult>;

  /**
   * Supplies the recovery factor. envelock ships no UI, so this is required.
   *
   * This is **not** your app's login credential (spec 0).
   */
  getRecoveryFactor(reason: RecoveryReason): Promise<RecoveryFactor>;

  onSecurityEvent?(event: SecurityEvent): void;

  /** Inactivity timeout before the DEK is zeroized. Default 5 minutes; `0` disables. */
  autoLockMs?: number;

  /** How long a provider callback may take before it becomes `unavailable`. Default 30 s. */
  callbackDeadlineMs?: number;

  /**
   * Failed recovery attempts before the vault is destroyed. Default 11, with a warning event at
   * 8. Only ever consulted for `passphrase` vaults - a `highEntropy` factor has no counter.
   * `null` disables destruction entirely.
   */
  destroyAfterAttempts?: number | null;

  /** Storage directory. Defaults to an app-private path chosen by the native module. */
  directory?: string;
}
