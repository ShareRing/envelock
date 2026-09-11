import { dropBuffer, installJSI, outstandingBuffers, putBuffer, takeBuffer } from '../jsi';

jest.mock('react-native', () => ({ NativeModules: {} }));

/**
 * Tests for the JavaScript half of the JSI buffer bridge.
 *
 * The host functions themselves are C++ and are tested in `cpp/EnvelockJSI.test.cpp`; a fake
 * registry stands in here so the TypeScript logic - subarray handling, single-use tokens,
 * releasing tokens on failure - can be exercised in Node.
 *
 * The subarray case is the one worth having. `bytes.buffer` on a `Uint8Array` view of a larger
 * allocation is the *whole* allocation, so passing it unguarded would send native code bytes
 * the caller never intended to hand over.
 */

interface FakeRegistry {
  buffers: Map<number, Uint8Array>;
  next: number;
}

function installFakeRegistry(): FakeRegistry {
  const registry: FakeRegistry = { buffers: new Map(), next: 0 };

  globalThis.__envelockPutBuffer = (buffer: ArrayBuffer) => {
    const token = ++registry.next;
    registry.buffers.set(token, new Uint8Array(buffer.slice(0)));
    return token;
  };
  globalThis.__envelockTakeBuffer = (token: number) => {
    const bytes = registry.buffers.get(token);
    if (bytes === undefined) throw new Error('unknown or already-redeemed buffer token');
    registry.buffers.delete(token);
    return bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
  };
  globalThis.__envelockDropBuffer = (token: number) => {
    registry.buffers.delete(token);
  };
  globalThis.__envelockBufferCount = () => registry.buffers.size;

  return registry;
}

describe('the JSI buffer bridge', () => {
  let registry: FakeRegistry;

  beforeEach(() => {
    registry = installFakeRegistry();
    installJSI();
  });

  afterEach(() => {
    globalThis.__envelockPutBuffer = undefined;
    globalThis.__envelockTakeBuffer = undefined;
    globalThis.__envelockDropBuffer = undefined;
    globalThis.__envelockBufferCount = undefined;
  });

  it('round-trips bytes at every length from 0 to 256', () => {
    for (let n = 0; n <= 256; n++) {
      const bytes = new Uint8Array(Array.from({ length: n }, (_, i) => (i * 31 + 7) % 256));
      const token = putBuffer(bytes);
      expect(Array.from(takeBuffer(token))).toEqual(Array.from(bytes));
    }
    expect(outstandingBuffers()).toBe(0);
  });

  it('round-trips every byte value', () => {
    const all = new Uint8Array(256).map((_, i) => i);
    expect(Array.from(takeBuffer(putBuffer(all)))).toEqual(Array.from(all));
  });

  /**
   * The case a naive `bytes.buffer` gets wrong: a view onto part of a larger allocation must
   * send only its own bytes, not the whole backing store.
   */
  it('sends only a subarray, not its whole backing buffer', () => {
    const backing = new Uint8Array(64).map((_, i) => i);
    const view = backing.subarray(8, 16);

    expect(view.byteOffset).toBe(8);
    expect(view.buffer.byteLength).toBe(64);

    const round = takeBuffer(putBuffer(view));
    expect(round.length).toBe(8);
    expect(Array.from(round)).toEqual([8, 9, 10, 11, 12, 13, 14, 15]);
  });

  it('sends a whole buffer without copying it when the view is exact', () => {
    const exact = new Uint8Array([1, 2, 3, 4]);
    expect(Array.from(takeBuffer(putBuffer(exact)))).toEqual([1, 2, 3, 4]);
  });

  /** A stale token must not resurrect a payload that was already consumed. */
  it('makes tokens single-use', () => {
    const token = putBuffer(new Uint8Array([9, 9]));
    takeBuffer(token);
    expect(() => takeBuffer(token)).toThrow(/already-redeemed|unknown/);
  });

  it('gives out distinct tokens', () => {
    const tokens = new Set<number>();
    for (let i = 0; i < 50; i++) tokens.add(putBuffer(new Uint8Array([i])));
    expect(tokens.size).toBe(50);
  });

  it('releases a dropped token without reading it', () => {
    const token = putBuffer(new Uint8Array([1, 2, 3]));
    expect(outstandingBuffers()).toBe(1);

    dropBuffer(token);
    expect(outstandingBuffers()).toBe(0);
    expect(() => takeBuffer(token)).toThrow();
  });

  it('tolerates dropping an unknown token', () => {
    expect(() => dropBuffer(999)).not.toThrow();
    expect(() => dropBuffer(0)).not.toThrow();
  });

  it('handles an empty payload', () => {
    const token = putBuffer(new Uint8Array(0));
    const round = takeBuffer(token);
    expect(round.length).toBe(0);
  });

  it('is idempotent to install twice', () => {
    const put = globalThis.__envelockPutBuffer;
    installJSI();
    expect(globalThis.__envelockPutBuffer).toBe(put);
  });

  it('leaves nothing outstanding after a normal exchange', () => {
    const token = putBuffer(new Uint8Array([1, 2, 3]));
    takeBuffer(token);
    expect(registry.buffers.size).toBe(0);
  });
});

describe('installJSI without a native module', () => {
  beforeEach(() => {
    globalThis.__envelockPutBuffer = undefined;
    globalThis.__envelockTakeBuffer = undefined;
  });

  /**
   * The two failures integrators actually hit are a missing `pod install` and a remote
   * debugger, which has no JSI runtime at all. Both need to say so, not fail obscurely later
   * when a buffer function turns out to be undefined.
   */
  it('explains a missing native module', () => {
    expect(() => installJSI()).toThrow(/native module is not linked|pod install/);
  });

  it('refuses to report success when nothing was installed', () => {
    jest.resetModules();
    jest.doMock('react-native', () => ({
      NativeModules: { RNEnvelockJSI: { install: () => true } },
    }));

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { installJSI: freshInstall } = require('../jsi') as typeof import('../jsi');
    expect(() => freshInstall()).toThrow(/installed nothing/);
  });
});
