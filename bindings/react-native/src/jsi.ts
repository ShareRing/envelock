import { NativeModules } from 'react-native';

/**
 * The JSI buffer bridge.
 *
 * React Native's codegen has no `Uint8Array`, so a TurboModule call can only carry strings.
 * Base64 would cost an encode and a decode on the JS thread and, worse, leave the material in an
 * immutable JS `string` that cannot be zeroized and lingers until the heap is collected.
 *
 * So bytes go straight into native memory through a JSI host function and the TurboModule call
 * carries only a numeric token. Nothing sensitive is ever a JS string, and every payload is
 * zeroized on release. Tokens are single-use, so a stale one cannot resurrect a payload that has
 * already been read.
 */

declare global {
  /** Copy an `ArrayBuffer` into native memory. Returns a single-use token. */
  // eslint-disable-next-line no-var
  var __envelockPutBuffer: ((buffer: ArrayBuffer) => number) | undefined;
  /** Redeem a token for an `ArrayBuffer`. Throws for an unknown or spent token. */
  // eslint-disable-next-line no-var
  var __envelockTakeBuffer: ((token: number) => ArrayBuffer) | undefined;
  /** Release a token nobody will redeem, zeroizing what it held. */
  // eslint-disable-next-line no-var
  var __envelockDropBuffer: ((token: number) => void) | undefined;
  /** Outstanding token count. Diagnostics and tests only. */
  // eslint-disable-next-line no-var
  var __envelockBufferCount: (() => number) | undefined;
}

let installed = false;

/**
 * Install the JSI host functions. Idempotent, and called automatically by `Vault.create`.
 *
 * @throws if the native module is missing or the runtime is unavailable - most often a
 *   forgotten `pod install`, or a debug session attached to a remote JS runtime, where JSI is
 *   not available at all.
 */
export function installJSI(): void {
  if (installed && typeof globalThis.__envelockPutBuffer === 'function') return;

  if (typeof globalThis.__envelockPutBuffer !== 'function') {
    const installer =
      (NativeModules.RNEnvelockJSI as { install?: () => boolean } | undefined) ??
      (NativeModules.RNEnvelock as { install?: () => boolean } | undefined);

    if (typeof installer?.install !== 'function') {
      throw new Error(
        'envelock: the native module is not linked. Run `pod install` on iOS, or rebuild the ' +
          'Android app so the envelock_jsi library is packaged.',
      );
    }
    if (installer.install() !== true) {
      throw new Error(
        'envelock: could not install its JSI functions. This happens when JavaScript is ' +
          'running in a remote debugger, which has no JSI runtime - use Hermes debugging ' +
          'instead.',
      );
    }
  }

  if (typeof globalThis.__envelockPutBuffer !== 'function') {
    throw new Error('envelock: JSI installation reported success but installed nothing.');
  }
  installed = true;
}

function required<T>(fn: T | undefined, name: string): T {
  if (fn === undefined) {
    throw new Error(`envelock: ${name} is unavailable; call installJSI() first.`);
  }
  return fn;
}

/**
 * Hand bytes to native memory and return the token to pass across the bridge.
 *
 * A `Uint8Array` that is a view onto part of a larger buffer is copied to its own buffer
 * first - otherwise native code would read the whole backing store, which for a subarray of a
 * larger allocation means reading bytes the caller never intended to send.
 */
export function putBuffer(bytes: Uint8Array): number {
  const put = required(globalThis.__envelockPutBuffer, '__envelockPutBuffer');

  const exact =
    bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
      ? bytes.buffer
      : bytes.slice().buffer;

  return put(exact as ArrayBuffer);
}

/** Redeem a token for its bytes. */
export function takeBuffer(token: number): Uint8Array {
  const take = required(globalThis.__envelockTakeBuffer, '__envelockTakeBuffer');
  return new Uint8Array(take(token));
}

/**
 * Release a token without reading it.
 *
 * Called when an operation fails after a token was created, so an abandoned payload does not
 * sit in native memory until the process exits.
 */
export function dropBuffer(token: number): void {
  globalThis.__envelockDropBuffer?.(token);
}

/** Outstanding token count. Useful in tests to assert nothing was leaked. */
export function outstandingBuffers(): number {
  return globalThis.__envelockBufferCount?.() ?? 0;
}
