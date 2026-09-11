# envelock

Encrypted local storage for Flutter, backed by the Secure Enclave on iOS and the Android
Keystore.

Envelope encryption with a hardware-gated key on one side and a recovery path on the other, so
the everyday flow is a single biometric prompt and a lost device is not a lost vault.

```dart
final vault = await Vault.open(
  VaultOptions(
    providerId: 'acme-v1',
    getKeyMaterial: (ctx) async => KeyMaterial(
      material: await fetchPepperFromYourBackend(),
      keyId: 'pepper-2026-01',
    ),
    getRecoveryFactor: (reason) async => RecoveryFactor.highEntropy(recoveryKey),
  ),
);

await vault.enroll(RecoveryFactor.highEntropy(recoveryKey));  // first run only
await vault.unlock();                                         // one biometric prompt
await vault.put('note', utf8.encode('hi'));
final Uint8List? note = await vault.get('note');
```

## The one rule

`getKeyMaterial` must be **deterministic**: for a given `keyId`, return byte-identical material
every single call. Break that and the vault stops opening.

Safe sources are a server-held per-user pepper, or WebAuthn PRF output for a fixed salt. What
bricks user data: bearer or refresh tokens, anything carrying a timestamp or request id, mutable
device fingerprints, and anything derived from a login credential the user can change.

`package:envelock/testing.dart` ships an assertion for this. Run it in CI.

## Platforms

iOS 15+ and Android API 23+. Web and desktop are refused explicitly with
`platformUnsupported` rather than falling back to a software key that would report the same
security posture while providing none of it.

## Setup

The iOS side needs `EnvelockCore`, which is distributed as a GitHub Release asset rather than
through CocoaPods trunk. Add this to your app's `Podfile`:

```ruby
pod 'EnvelockCore', :podspec => 'https://github.com/ShareRing/envelock/releases/download/v0.1.0/EnvelockCore.podspec'
```

Android resolves `network.sharering:envelock-android` from Maven Central automatically.

## Documentation

Full documentation, the specification and runnable examples for every platform are at
[github.com/ShareRing/envelock](https://github.com/ShareRing/envelock).

## License

Apache-2.0
