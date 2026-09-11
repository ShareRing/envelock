# @sharering/react-native-envelock

Encrypted local storage for React Native, backed by the Secure Enclave on iOS and the Android
Keystore.

Envelope encryption with a hardware-gated key on one side and a recovery path on the other, so
the everyday flow is a single biometric prompt and a lost device is not a lost vault.

```ts
import { Vault } from '@sharering/react-native-envelock';

const vault = await Vault.create({
  providerId: 'acme-v1',
  getKeyMaterial: async (ctx) => ({
    material: await fetchPepperFromYourBackend(),
    keyId: 'pepper-2026-01',
  }),
  getRecoveryFactor: async (reason) => ({ kind: 'highEntropy', bytes: recoveryKey }),
});

await vault.unlock();                                  // one biometric prompt
await vault.put('note', new TextEncoder().encode('hi'));
const note = await vault.get('note');
```

## The one rule

`getKeyMaterial` must be **deterministic**: for a given `keyId`, return byte-identical material
every single call. Break that and the vault stops opening.

Safe sources are a server-held per-user pepper, or WebAuthn PRF output for a fixed salt. What
bricks user data: bearer or refresh tokens, anything carrying a timestamp or request id, mutable
device fingerprints, and anything derived from a login credential the user can change.

`@sharering/react-native-envelock/testing` ships an assertion for this. Run it in CI.

## Bytes never become JavaScript strings

Record payloads and provider material travel to native memory through a JSI buffer registry, so
key material never sits in an immutable JS string waiting on the garbage collector. The data
encryption key never crosses the bridge at all.

## Platforms

iOS 15+ and Android API 24+. Web and desktop are refused explicitly with `platformUnsupported`
rather than falling back to a software key that would report the same security posture while
providing none of it.

## Setup

The iOS side needs `EnvelockCore`, which is distributed as a GitHub Release asset rather than
through CocoaPods trunk. Add this to your app's `Podfile` before `pod install`:

```ruby
pod 'EnvelockCore', :podspec => 'https://github.com/ShareRing/envelock/releases/download/v0.1.0/EnvelockCore.podspec'
```

Android resolves `network.sharering:envelock-android` from Maven Central automatically.

## Documentation

Full documentation, the specification and runnable examples for every platform are at
[github.com/ShareRing/envelock](https://github.com/ShareRing/envelock).

## License

Apache-2.0
