import { AppState, NativeEventEmitter, NativeModules, type AppStateStatus } from 'react-native';

import { dropBuffer, installJSI, putBuffer, takeBuffer } from './jsi';
import NativeEnvelock, { assertPlatformSupported } from './NativeEnvelock';
import {
  VaultError,
  type HardwareBacking,
  type KeyMaterialResult,
  type MaterialReason,
  type RecoveryFactor,
  type RecoveryReason,
  type SecurityEvent,
  type SecurityInfo,
  type VaultErrorCode,
  type VaultOptions,
  type VaultState,
} from './types';

export * from './types';
export { assertPlatformSupported } from './NativeEnvelock';
export { installJSI, outstandingBuffers } from './jsi';
// `assertProviderDeterministic` is deliberately NOT re-exported here. Spec 7.5 puts the
// determinism harness on a `/testing` subpath so a production bundle cannot reach it through
// the main entry point:
//
//   import { assertProviderDeterministic } from '@sharering/react-native-envelock/testing';

const EVENT_KEY_MATERIAL = 'envelock:getKeyMaterial';
const EVENT_RECOVERY = 'envelock:getRecoveryFactor';
const EVENT_SECURITY = 'envelock:securityEvent';

// ---------------------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------------------

/**
 * Subscribe to a native event with a typed payload.
 *
 * `NativeEventEmitter` types its listener as `(...args: readonly Object[])`, because the bridge
 * cannot know what native will send. These payload shapes are defined by envelock's own native
 * modules a few files away, so narrowing once here is honest - and it keeps the assertion out
 * of every call site.
 */
function onNativeEvent<T>(
  emitter: NativeEventEmitter,
  event: string,
  handler: (payload: T) => void,
): { remove(): void } {
  return emitter.addListener(event, (...args: readonly Object[]) => handler(args[0] as T));
}

const ERROR_CODES: readonly VaultErrorCode[] = [
  'cancelled',
  'unavailable',
  'denied',
  'misconfigured',
  'providerMaterialMismatch',
  'providerKeyRotated',
  'materialRejected',
  'corruptData',
  'unexpected',
  'platformUnsupported',
];

/**
 * Map anything a native call rejected with onto the documented taxonomy.
 *
 * An unrecognised code becomes `unavailable`: retryable and uncounted. Defaulting to `denied`
 * would let a transport hiccup march a legitimate user toward lockout (spec 7.4).
 */
function toVaultError(e: unknown): VaultError {
  if (e instanceof VaultError) return e;
  const code = (e as { code?: string })?.code;
  const message = (e as { message?: string })?.message;
  if (typeof code === 'string' && (ERROR_CODES as readonly string[]).includes(code)) {
    return new VaultError(code as VaultErrorCode, message);
  }
  return new VaultError('unavailable', message ?? String(e));
}

export class Vault {
  private readonly subscriptions: { remove(): void }[] = [];
  private appStateSub: { remove(): void } | undefined;

  private constructor(
    private readonly options: VaultOptions,
    readonly directory: string,
  ) {}

  /**
   * Create the vault and wire up the provider callbacks.
   *
   * ## Lifecycle
   *
   * This installs an `AppState` listener that calls {@link Vault.lock} when the app
   * backgrounds. Zeroization happens inside the Rust core - dropping a JS reference gives no
   * guarantee the key bytes ever leave memory (spec 11.3).
   */
  static async create(options: VaultOptions): Promise<Vault> {
    // First, so web and desktop get `platformUnsupported` rather than a JSI installation
    // failure that reads like a broken build (spec 6.4).
    assertPlatformSupported();

    // Must happen before anything sends or receives bytes.
    installJSI();

    const emitter = new NativeEventEmitter(NativeModules.RNEnvelock);

    const directory = await NativeEnvelock.create({
      providerId: options.providerId,
      directory: options.directory ?? null,
      autoLockMs: options.autoLockMs ?? 300_000,
      callbackDeadlineMs: options.callbackDeadlineMs ?? 30_000,
      destroyAfterAttempts:
        options.destroyAfterAttempts === undefined ? 11 : options.destroyAfterAttempts,
    });

    const vault = new Vault(options, directory);

    vault.subscriptions.push(
      onNativeEvent<{
        requestId: string;
        reason: MaterialReason;
        nonceToken: number;
        deadlineMs: number;
      }>(emitter, EVENT_KEY_MATERIAL, (e) => {
          void vault.serve(e.requestId, async () => {
            const result = await options.getKeyMaterial({
              reason: e.reason,
              nonce: takeBuffer(e.nonceToken),
              deadlineMs: e.deadlineMs,
            });
            return {
              token: putBuffer(result.material),
              // Packed into the text field so native can rebuild the record in one round trip.
              text: [
                result.keyId,
                result.cacheable ?? true,
                result.cacheTtlMs ?? 30 * 24 * 60 * 60 * 1000,
              ].join(' '),
            };
          });
      }),
    );

    vault.subscriptions.push(
      onNativeEvent<{ requestId: string; reason: RecoveryReason }>(
        emitter,
        EVENT_RECOVERY,
        (e) => {
          void vault.serve(e.requestId, async () => {
            const factor = await options.getRecoveryFactor(e.reason);
            return factor.kind === 'highEntropy'
              ? { token: putBuffer(factor.bytes), text: 'highEntropy' }
              : { token: 0, text: `passphrase ${factor.value}` };
          });
        },
      ),
    );

    if (options.onSecurityEvent) {
      const handler = options.onSecurityEvent.bind(options);
      vault.subscriptions.push(
        onNativeEvent<SecurityEvent>(emitter, EVENT_SECURITY, handler),
      );
    }

    // `background`, not `!== 'active'`. iOS reports `inactive` for the OS biometric sheet, the
    // app switcher and Control Centre, all of which happen while the app is still in use - and
    // the biometric sheet is raised by `unlock()` itself, so locking there zeroizes the DEK the
    // user just authenticated for and the next read fails with "vault is locked".
    vault.appStateSub = AppState.addEventListener('change', (status: AppStateStatus) => {
      if (status === 'background') void vault.lock();
    });

    return vault;
  }

  /**
   * Run a provider callback and hand the outcome back to native code.
   *
   * Native is blocking a background thread on this, so it must always resolve exactly once -
   * including when the user's callback throws something that is not a `VaultError`.
   */
  private async serve(
    requestId: string,
    run: () => Promise<{ token: number; text: string }>,
  ): Promise<void> {
    let token = 0;
    try {
      const answer = await run();
      token = answer.token;
      NativeEnvelock.resolveCallback(requestId, answer.token, answer.text, '', '');
    } catch (e) {
      // A token created before the failure must be released, or the payload sits in native
      // memory until the process exits.
      if (token !== 0) dropBuffer(token);
      const err = toVaultError(e);
      NativeEnvelock.resolveCallback(requestId, 0, '', err.code, err.message);
    }
  }

  async state(): Promise<VaultState> {
    const raw = await NativeEnvelock.state();
    if (raw.startsWith('locked_out:')) {
      return { state: 'locked_out', untilMs: Number(raw.slice('locked_out:'.length)) };
    }
    return { state: raw as Exclude<VaultState['state'], 'locked_out'> } as VaultState;
  }

  /** Enroll. Prompts once for enclave consent, then fetches material. */
  enroll(factor: RecoveryFactor): Promise<void> {
    return this.withFactor(factor, (kind, token, passphrase) =>
      NativeEnvelock.enroll(kind, token, passphrase),
    );
  }

  /** Primary path: one OS biometric prompt, cached material, works offline (spec 8.2). */
  unlock(): Promise<void> {
    return this.call(() => NativeEnvelock.unlock());
  }

  /**
   * Recovery path. Provisions a fresh enclave key and rewraps the primary path in the same
   * operation, so the *next* unlock is biometric-only (spec 8.4).
   */
  unlockWithRecovery(): Promise<void> {
    return this.call(() => NativeEnvelock.unlockWithRecovery());
  }

  changeRecoveryFactor(factor: RecoveryFactor): Promise<void> {
    return this.withFactor(factor, (kind, token, passphrase) =>
      NativeEnvelock.changeRecoveryFactor(kind, token, passphrase),
    );
  }

  async put(recordId: string, value: Uint8Array): Promise<void> {
    const token = putBuffer(value);
    try {
      await this.call(() => NativeEnvelock.put(recordId, token));
    } catch (e) {
      // Native consumes the token on success. On failure it may not have, so release it.
      dropBuffer(token);
      throw e;
    }
  }

  async get(recordId: string): Promise<Uint8Array | null> {
    const token = await this.call(() => NativeEnvelock.get(recordId));
    return token === 0 ? null : takeBuffer(token);
  }

  delete(recordId: string): Promise<void> {
    return this.call(() => NativeEnvelock.remove(recordId));
  }

  list(prefix = ''): Promise<string[]> {
    return this.call(() => NativeEnvelock.list(prefix));
  }

  /** Zeroize the in-memory DEK. Called automatically when the app backgrounds. */
  lock(): Promise<void> {
    return this.call(() => NativeEnvelock.lock());
  }

  /** Irreversible: deletes the enclave key, envelope, cache and every record. */
  destroy(): Promise<void> {
    return this.call(() => NativeEnvelock.destroyVault());
  }

  async securityInfo(): Promise<SecurityInfo> {
    const raw = await this.call(() => NativeEnvelock.securityInfo());
    const parsed = JSON.parse(raw) as SecurityInfo & { hardwareBacking: HardwareBacking };
    return parsed;
  }

  /** Detach listeners. Call when tearing the vault down; it does not delete any data. */
  async dispose(): Promise<void> {
    this.appStateSub?.remove();
    this.appStateSub = undefined;
    for (const s of this.subscriptions.splice(0)) s.remove();
    await NativeEnvelock.destroyInstance();
  }

  private async call<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      throw toVaultError(e);
    }
  }

  /** Hand a recovery factor to native code, releasing the token if the call fails. */
  private async withFactor(
    factor: RecoveryFactor,
    fn: (kind: string, token: number, passphrase: string) => Promise<void>,
  ): Promise<void> {
    const token = factor.kind === 'highEntropy' ? putBuffer(factor.bytes) : 0;
    try {
      await this.call(() =>
        fn(factor.kind, token, factor.kind === 'passphrase' ? factor.value : ''),
      );
    } catch (e) {
      if (token !== 0) dropBuffer(token);
      throw e;
    }
  }
}
