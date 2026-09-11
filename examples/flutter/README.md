# envelock Flutter demo

Drives the whole vault lifecycle against the real Secure Enclave and Android Keystore: enroll,
lock, unlock, recover, put/get/list/delete, and destroy.

`lib/providers.dart` is the part worth reading. It is a working `getKeyMaterial` and
`getRecoveryFactor` pair (the entire surface an integrator has to write) and it ships both
shapes: `LocalDemoMaterialProvider` so the app runs with no backend, and
`BackendMaterialProvider` for a real one.

## Run it

```sh
# The plugin consumes the built native libraries, not the Rust source.
../../platform/android/build-jni.sh
(cd ../../platform/android && ./gradlew publishToMavenLocal)
../../platform/ios/build-xcframework.sh

flutter run
```

Enrollment needs a device with a secure lock screen. On a simulator with none, enrollment fails
rather than proceeding unprotected - that is the security floor, not a bug.

## What the local provider fakes, and what it gets right

`LocalDemoMaterialProvider` generates a 32-byte pepper once and stores it in app storage. That
is **not a second factor**: the pepper sits next to the envelope, so a rooted or jailbroken
device yields both and the material adds nothing the enclave key was not already contributing.
The vault is still protected by the hardware key behind its OS gate, but you no longer get two
independent factors. Point `BackendMaterialProvider` at [`examples/reference-backend`](../reference-backend) for that.

What it does get right is the part integrators break: the bytes are written once and read back
forever, cached in memory **and** on disk. Memory alone passes a determinism check inside one
process and bricks the vault on the next cold start - the exact bug
`assertProviderDeterministic(acrossRestarts:)` exists to catch.

`DemoRecoveryProvider` returns a fixed 32-byte `highEntropy` factor so the recovery path can be
exercised without a wallet. A real wallet derives it with `envelock-bip85` from the BIP-39 seed
at a hardened path, and never lets the seed phrase itself reach envelock.

## Two demos in one app

The app opens on **Vault directly**: envelock as a standalone library, driven by the app
itself. The other tab, **Inside an SDK**, runs the same vault through `lib/sharering_vault_sdk.dart`: a demo wrapper
that hides the vault behind `initialize` / `getDocument` / `getRecoveryFactor` / `destroy`, the
way a product SDK with envelock baked in would.

The wrapper is example code. Nothing in envelock depends on it, and installing envelock does not
install it - see [examples/README.md](../README.md) for what it does and the two caveats worth
knowing before copying it.

