# envelock React Native demo

Drives the whole vault lifecycle against the real Secure Enclave and Android Keystore: enroll,
lock, unlock, recover, put/get/list/delete, and destroy.

`providers.ts` is the part worth reading. It is a working `getKeyMaterial` and
`getRecoveryFactor` pair (the entire surface an integrator has to write) and it ships both
shapes: `localDemoMaterialProvider` so the app runs with no backend, and
`backendMaterialProvider` for a real one.

## Run it

```sh
# The binding consumes the built native libraries, not the Rust source.
../../platform/android/build-jni.sh
(cd ../../platform/android && ./gradlew publishToMavenLocal)
../../platform/ios/build-xcframework.sh

npm install
(cd ios && pod install)

npm run ios        # or: npm run android
```

The package is linked from source (`file:../../bindings/react-native`), so a change in the
binding shows up on the next Metro reload.

Enrollment needs a device with a secure lock screen. On a simulator with none, enrollment fails
rather than proceeding unprotected - that is the security floor, not a bug.

## Two demos in one app

The app opens on **Vault directly**: envelock as a standalone library, driven by the app
itself. The other tab, **Inside an SDK**, runs the same vault through `sdk.ts`: a demo wrapper
that hides the vault behind `initialize` / `getDocument` / `getRecoveryFactor` / `destroy`, the
way a product SDK with envelock baked in would.

The wrapper is example code. Nothing in envelock depends on it, and installing envelock does not
install it - see [examples/README.md](../README.md) for what it does and the two caveats worth
knowing before copying it.

## What the local provider fakes, and what it gets right

`localDemoMaterialProvider` stretches a stable local seed into 32 bytes with FNV-1a. That is
**not a second factor** and not real key material. A device-derived value adds nothing the
enclave key was not already contributing. The vault is still protected by the hardware key
behind its OS gate, but you no longer get two independent factors. Point
`backendMaterialProvider` at [`examples/reference-backend`](../reference-backend) for that.

What it does get right is the part integrators break: the same bytes come back on every call and
after a cold start, because they are recomputed from a stable seed rather than only memoized in
a module-level variable. Memoizing alone passes a determinism check inside one process and
bricks the vault on the next cold start - the exact bug
`assertProviderDeterministic({ acrossRestarts })` exists to catch.

`demoRecoveryProvider` returns a fixed 32-byte `highEntropy` factor so the recovery path can be
exercised without a wallet. A real wallet derives it with `envelock-bip85` from the BIP-39 seed
at a hardened path, and never lets the seed phrase itself reach envelock.

## If an Android build fails after you fixed the cause

Gradle caches autolinking output, so a stale `Android-autolinking.cmake` keeps failing:

```sh
rm -rf android/build android/.gradle android/app/build android/app/.cxx
```

