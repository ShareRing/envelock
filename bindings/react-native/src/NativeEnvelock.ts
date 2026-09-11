import type { TurboModule } from 'react-native';
import { Platform, TurboModuleRegistry } from 'react-native';

import { VaultError } from './types';

/**
 * The native module interface. Strings, numbers and promises only.
 *
 * Byte payloads never cross here: they go through the JSI buffer registry and only a numeric
 * token comes this way (see `jsi.ts`). That satisfies spec 11.3, whose concern is key material
 * stuck in an immutable JS `string` that cannot be zeroized. The DEK never crosses at all.
 *
 * ## Why this is not a codegen'd TurboModule
 *
 * The native implementations are bridge modules, reached through `TurboModuleRegistry`, which
 * resolves them on both architectures. Declaring `codegenConfig` would generate C++ specs that
 * nothing implements and the build would fail looking for them. Full codegen would buy latency,
 * not security, because the path carrying secrets is JSI either way.
 */
export interface Spec extends TurboModule {
  /** Create the vault. Returns the resolved storage directory. */
  create(config: {
    providerId: string;
    directory: string | null;
    autoLockMs: number;
    callbackDeadlineMs: number;
    destroyAfterAttempts: number | null;
  }): Promise<string>;

  destroyInstance(): Promise<void>;

  /** `not_enrolled` | `locked` | `unlocked` | `locked_out:<untilMs>` | `needs_recovery`. */
  state(): Promise<string>;

  /**
   * `kind` is `highEntropy` or `passphrase`. A high-entropy factor arrives as a buffer
   * `token`; a passphrase is inherently a string, so there is nothing to gain by tokenizing it.
   */
  enroll(kind: string, token: number, passphrase: string): Promise<void>;

  unlock(): Promise<void>;
  unlockWithRecovery(): Promise<void>;
  changeRecoveryFactor(kind: string, token: number, passphrase: string): Promise<void>;

  /** `token` names bytes already handed to the JSI buffer registry. */
  put(recordId: string, token: number): Promise<void>;
  /** Returns a token to redeem for an `ArrayBuffer`, or `0` for a missing record. */
  get(recordId: string): Promise<number>;
  remove(recordId: string): Promise<void>;
  list(prefix: string): Promise<string[]>;

  lock(): Promise<void>;
  destroyVault(): Promise<void>;
  securityInfo(): Promise<string>;

  /**
   * Hand a provider callback's outcome back to native code.
   *
   * Native invokes the JS provider by emitting an event and blocking a background thread on a
   * semaphore. This resolves that wait. An empty `errorCode` means success; `token` is `0`
   * when there are no bytes to return.
   */
  resolveCallback(
    requestId: string,
    token: number,
    text: string,
    errorCode: string,
    errorMessage: string,
  ): void;

  /** Install the JSI host functions. See `jsi.ts`. */
  install(): boolean;

  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

const SUPPORTED = Platform.OS === 'ios' || Platform.OS === 'android';

/**
 * Fail with `platformUnsupported` where there is no enclave (spec 6.4).
 *
 * envelock's security floor is a hardware-backed, biometric-gated key. Web and desktop have
 * neither, and section 6.4 refuses rather than falling back to a software key that would report the
 * same posture while providing none of it.
 *
 * A *missing native module on iOS or Android* is a different failure - a broken build, not an
 * unsupported platform - and `installJSI` already names it with the fix. The two must not
 * collapse into one code.
 */
export function assertPlatformSupported(): void {
  if (!SUPPORTED) {
    throw new VaultError(
      'platformUnsupported',
      `envelock requires iOS or Android: it is backed by the Secure Enclave or the Android ` +
        `Keystore, and ${Platform.OS} has neither.`,
    );
  }
}

/**
 * `get`, not `getEnforcing`, and never called off iOS/Android.
 *
 * `getEnforcing` throws while this module is being *imported*, so the app would die at
 * `import` with "TurboModule could not be found" before any envelock code could report the
 * real reason. react-native-web goes further and ships no `TurboModuleRegistry` at all, so
 * even reaching into it has to stay behind the platform check.
 *
 * Every call site is reached through `Vault`, which calls {@link assertPlatformSupported}
 * first, so by the time a method here runs the module exists.
 */
export default (SUPPORTED ? TurboModuleRegistry.get<Spec>('RNEnvelock') : undefined) as Spec;
