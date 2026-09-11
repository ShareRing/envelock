/**
 * A stand-in for a host SDK that has envelock baked in - the layer an external app installs.
 *
 * envelock is *inside* this file, not in the app above it. The app never sees `Vault`, never
 * calls `put`/`get`/`list`, and never learns that a state machine exists. It gets four entry
 * points: `initialize`, `destroy`, `getDocument`, `getRecoveryFactor`.
 *
 * envelock does not depend on any of this, and nothing here is part of the library: it is a
 * worked example of wrapping a standalone vault inside a product SDK. `App.tsx` drives the
 * same vault directly, which is the other half of the picture.
 */

// Installs `crypto.getRandomValues`. React Native ships no CSPRNG, and the recovery phrase is
// a secret: `Math.random` is not an acceptable source for it.
import 'react-native-get-random-values';

import {
  Vault,
  VaultError,
  type KeyMaterialResult,
  type MaterialContext,
  type RecoveryFactor,
  type RecoveryReason,
  type SecurityEvent,
} from '@sharering/react-native-envelock';

import wordlist from '../shared/bip39-english.json';

import { utf8Decode, utf8Encode } from './providers';
import { stepFor, type SdkStep } from './sdkState';

export { stepFor, type SdkStep };

// The polyfill above installs this; React Native's own types do not declare it.
declare const crypto: { getRandomValues<T extends ArrayBufferView>(array: T): T };

/** What the app hands the SDK. Everything envelock-shaped is here, and nothing else. */
export interface SdkVaultOptions {
  /** Namespaced into every derivation. **Changing it invalidates every existing vault.** */
  providerId: string;
  /** Must return byte-identical material every call. */
  getKeyMaterial(ctx: MaterialContext): Promise<KeyMaterialResult>;
  /**
   * Asked for the 12 words on a device that has never held them: a restored backup, a new
   * phone. The SDK holds the phrase for the life of a session, so this fires rarely - but
   * there is no way around it, because the enclave key cannot travel between devices.
   */
  promptRecoveryPhrase(reason: RecoveryReason): Promise<string>;
  onSecurityEvent?(event: SecurityEvent): void;
  autoLockMs?: number;
}

export interface SdkOptions {
  appId: string;
  vaultOptions: SdkVaultOptions;
  /**
   * Where a document comes from the first time. After that it is served from the vault,
   * offline, with no network call - that is the point of the vault.
   */
  fetchDocument(documentId: string): Promise<Uint8Array>;
}

const PHRASE_RECORD = 'sys:recovery-phrase';

/** 12 words drawn from the BIP-39 English list with the platform CSPRNG: 132 bits. */
export function generateRecoveryPhrase(): string {
  const words: string[] = [];
  const indices = new Uint32Array(12);
  crypto.getRandomValues(indices);
  for (const index of indices) {
    // Rejection-free and unbiased: 2048 divides 2^32 exactly, so a plain mask is uniform.
    words.push(wordlist[index & 0x7ff]);
  }
  return words.join(' ');
}

export class ShareRingVaultSdk {
  private vault!: Vault;

  /**
   * Held in memory only. Persisted inside the vault, never beside it: app storage is
   * plaintext on a rooted device and the phrase opens everything.
   */
  private phrase?: string;

  private constructor(private readonly options: SdkOptions) {}

  /**
   * Opens the vault and enrolls if this is the first run.
   *
   * One call per app process. It installs an `AppState` listener that locks on background, so
   * a second instance would fight the first.
   */
  static async initialize(options: SdkOptions): Promise<ShareRingVaultSdk> {
    const sdk = new ShareRingVaultSdk(options);
    const v = options.vaultOptions;

    sdk.vault = await Vault.create({
      providerId: v.providerId,
      getKeyMaterial: v.getKeyMaterial,
      // The app supplies material; the SDK owns recovery. This is why `getRecoveryFactor` is
      // absent from `SdkVaultOptions`.
      getRecoveryFactor: (reason) => sdk.recoveryFactor(reason),
      onSecurityEvent: v.onSecurityEvent,
      autoLockMs: v.autoLockMs,
    });

    await sdk.ready();
    return sdk;
  }

  /**
   * The 12 words. Show them once at setup and let the user write them down.
   *
   * Reading them needs an unlocked vault (they are stored in it) so this costs a biometric
   * prompt on a locked session, which is the correct price for revealing them.
   */
  async getRecoveryFactor(): Promise<string> {
    if (this.phrase) return this.phrase;

    await this.ready();
    const stored = await this.vault.get(PHRASE_RECORD);
    if (!stored) {
      throw new VaultError('corruptData', 'the vault is enrolled but holds no recovery phrase');
    }
    this.phrase = utf8Decode(stored);
    return this.phrase;
  }

  /** Cached in the vault after the first fetch; every later call is offline. */
  async getDocument(documentId: string): Promise<Record<string, unknown>> {
    await this.ready();

    const id = `doc:${documentId}`;
    const cached = await this.vault.get(id);
    if (cached) return JSON.parse(utf8Decode(cached)) as Record<string, unknown>;

    const fetched = await this.options.fetchDocument(documentId);
    await this.vault.put(id, fetched);
    return JSON.parse(utf8Decode(fetched)) as Record<string, unknown>;
  }

  /**
   * Irreversible: enclave key, envelope, cache and every document. The 12 words do not bring
   * this back - nothing does.
   */
  async destroy(): Promise<void> {
    await this.vault.destroy();
    await this.vault.dispose();
    this.phrase = undefined;
  }

  /** Drive the vault to `unlocked`, whatever it currently is. */
  private async ready(): Promise<void> {
    const state = await this.vault.state();

    switch (stepFor(state)) {
      case 'ready':
        return;

      case 'enroll': {
        // A passphrase factor, so the spec 10 backoff ladder applies and 11 failed attempts
        // destroy the vault. A wallet should derive 32 bytes from its seed with envelock-bip85
        // and enroll `highEntropy` instead, which carries no ladder at all.
        const phrase = generateRecoveryPhrase();
        await this.vault.enroll({ kind: 'passphrase', value: phrase });
        this.phrase = phrase;

        // Enrollment is atomic: a vault enrolled with a phrase that never reached storage is
        // unopenable by anyone, so tear it down rather than leave that behind.
        try {
          await this.vault.put(PHRASE_RECORD, utf8Encode(phrase));
        } catch (e) {
          await this.vault.destroy();
          this.phrase = undefined;
          throw e;
        }
        return;
      }

      case 'unlock':
        await this.vault.unlock();
        return;

      case 'recover':
        // Rewraps the primary path in the same operation, so the next unlock is biometric-only.
        await this.vault.unlockWithRecovery();
        return;

      case 'lockedOut':
        // Retrying here would burn an attempt against a ladder that is already throttling.
        throw new VaultError(
          'denied',
          `too many failed recovery attempts; retry after ${new Date(
            state.state === 'locked_out' ? state.untilMs : 0,
          ).toISOString()}`,
        );
    }
  }

  private async recoveryFactor(reason: RecoveryReason): Promise<RecoveryFactor> {
    const phrase = (this.phrase ?? (await this.options.vaultOptions.promptRecoveryPhrase(reason)))
      .trim()
      .replace(/\s+/g, ' ');

    // A mistyped word never reaches the KDF. Not `denied`: nothing was verified, so this must
    // not spend one of the 11 attempts (spec 7.4).
    const words = phrase.split(' ');
    if (words.length !== 12 || words.some((word) => !wordlist.includes(word))) {
      throw new VaultError('cancelled', 'that is not a valid 12-word phrase');
    }

    this.phrase = phrase;
    return { kind: 'passphrase', value: phrase };
  }
}
