import type { VaultError } from '../types';

/**
 * Spec 6.4: web and desktop must fail with `platformUnsupported`, not with a build error.
 *
 * The second assertion is the one that stops a regression. `TurboModuleRegistry` does not
 * exist in react-native-web, so resolving the native module unconditionally at import time
 * crashes with a `TypeError` before any envelock code can explain itself - which is strictly
 * worse than the "TurboModule could not be found" this replaced.
 */
function load(os: string) {
  jest.resetModules();
  const get = jest.fn(() => ({}));
  jest.doMock('react-native', () => ({ Platform: { OS: os }, TurboModuleRegistry: { get } }));
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require('../NativeEnvelock') as typeof import('../NativeEnvelock');
  return { mod, get };
}

for (const os of ['web', 'macos', 'windows']) {
  test(`${os} throws platformUnsupported and never touches TurboModuleRegistry`, () => {
    const { mod, get } = load(os);

    let caught: unknown;
    try {
      mod.assertPlatformSupported();
    } catch (e) {
      caught = e;
    }

    // Checked by `name`, not `instanceof`: `jest.resetModules()` hands the module under test
    // its own copy of `../types`, so the two `VaultError` constructors are not identical.
    expect((caught as VaultError).name).toBe('VaultError');
    expect((caught as VaultError).code).toBe('platformUnsupported');
    expect((caught as VaultError).message).toContain(os);
    expect(get).not.toHaveBeenCalled();
  });
}

for (const os of ['ios', 'android']) {
  test(`${os} is supported and resolves the native module`, () => {
    const { mod, get } = load(os);

    expect(() => mod.assertPlatformSupported()).not.toThrow();
    expect(get).toHaveBeenCalledWith('RNEnvelock');
    expect(mod.default).toBeDefined();
  });
}
