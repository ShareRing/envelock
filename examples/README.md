# Examples

Four apps, one library. Each app ships **two demos side by side**, switchable in the running
app:

| Demo | What it shows |
|---|---|
| **Vault directly** | envelock as a standalone library: the app itself drives `enroll`, `unlock`, `put`, `get`, `list`, `recover`, `destroy` |
| **Inside an SDK** | the same vault baked into a product SDK, which exposes four calls (`initialize`, `getDocument`, `getRecoveryFactor`, `destroy`) and never hands the app a vault |

Both demos exist to prove the same thing: **envelock is a standalone library**. It does not
know or care whether an app consumes it directly or through a wrapper. The wrapper in these
examples (`ShareRingVaultSdk`) is demo code that lives in the example. Nothing in envelock
depends on it, and installing envelock never installs it.

| Example | Direct demo | SDK demo | The wrapper |
|---|---|---|---|
| [`flutter`](flutter) | `lib/main.dart` | `lib/sdk_demo_screen.dart` | `lib/sharering_vault_sdk.dart` |
| [`react-native`](react-native) | `App.tsx` | `AppSdk.tsx` | `sdk.ts` |
| [`android`](android) | `MainActivity.kt` | `SdkDemoScreen.kt` | `ShareRingVaultSdk.kt` |
| [`ios`](ios) | `DemoApp.swift` | `SdkDemoScreen.swift` | `ShareRingVaultSdk.swift` |

Plus [`reference-backend`](reference-backend): a JWKS-verifying material endpoint, which every
example can point at instead of its local demo pepper.

## What the wrapper does, in every example

Identical shape on all four platforms, so they can be read against each other:

- `initialize(options)` opens the vault, and on first run enrolls it with a **12-word recovery
  phrase the SDK generates itself**. The app supplies `providerId` and `getKeyMaterial`; the SDK
  owns recovery, so there is no `getRecoveryFactor` in its options.
- `getDocument(id)` drives the vault to unlocked (`unlock`, or `unlockWithRecovery` on a
  restored backup), reads the document, and on a cache miss fetches it once and stores it. Every
  later call is offline.
- `getRecoveryFactor()` returns those 12 words, read back out of the vault, so it costs a
  biometric prompt on a locked session.
- `destroy()` deletes everything, irreversibly.

Two deliberate choices worth knowing before copying any of it:

**The phrase is enrolled as a `passphrase` factor**, so the spec 10 backoff ladder applies and
11 failed recovery attempts destroy the vault. A wallet should derive 32 bytes from its BIP-39
seed with [`envelock-bip85`](../bip85) and enroll a `highEntropy` factor instead: no ladder, no
destruction, and no seed phrase ever reaching envelock.

**Each wrapped vault gets its own storage directory**, because one directory holds one envelope.
That is what keeps the two demos in the same app from fighting over it.

`shared/bip39-english.json` is the BIP-39 English wordlist the Android, iOS and React Native
wrappers draw their words from, so there is one copy and three consumers. The Flutter example
uses the `bip39`
pub package instead, which carries its own list.

## Running them

Each example's README has its build steps. All of them need the native libraries built first -
the bindings consume built artifacts, not Rust source:

```sh
platform/android/build-jni.sh
(cd platform/android && ./gradlew publishToMavenLocal)
platform/ios/build-xcframework.sh
```

Enrollment needs a device with a secure lock screen. Without one it fails rather than proceeding
unprotected. That is the security floor, not a bug.
