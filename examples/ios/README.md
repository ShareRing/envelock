# envelock native iOS demo

Drives the whole vault lifecycle against the real Secure Enclave: enroll, lock, unlock, recover,
put/get/list/delete, and destroy.

`DemoProviders.swift` is the part worth reading. It is a working `getKeyMaterial` implementation
(most of the surface an integrator has to write) in both shapes: `LocalDemoMaterialProvider`
so the app runs with no backend, and `BackendMaterialProvider` for a real one.

## Run it

```sh
# The example consumes the built XCFramework, not the Rust source.
../../platform/ios/build-xcframework.sh

brew install xcodegen && xcodegen
open EnvelockDemo.xcodeproj
```

The project is generated rather than committed: a pbxproj is 2000 lines of machine-managed XML
that no human should review in a diff.

Run it on a physical device. The Simulator has no Secure Enclave - it still runs, and
`securityInfo()` reports `software` truthfully, but nothing is hardware-backed there.

## Two demos in one app

The app opens on **Vault directly**: envelock as a standalone library, driven by the app
itself. The other tab, **Inside an SDK**, runs the same vault through `ShareRingVaultSdk.swift`: a demo wrapper
that hides the vault behind `initialize` / `getDocument` / `getRecoveryFactor` / `destroy`, the
way a product SDK with envelock baked in would.

The wrapper is example code. Nothing in envelock depends on it, and installing envelock does not
install it - see [examples/README.md](../README.md) for what it does and the two caveats worth
knowing before copying it.

## What the local provider fakes, and what it gets right

`LocalDemoMaterialProvider` generates a 32-byte pepper once and stores it in app storage. That
is **not a second factor**: the pepper sits next to the envelope, so a jailbroken device yields
both and the material adds nothing the enclave key was not already contributing. The vault is
still protected by the hardware key behind its OS gate, but you no longer get two independent
factors. Point `BackendMaterialProvider` at
[`examples/reference-backend`](../reference-backend) for that.

What it does get right is the part integrators break: the bytes are written once and read back
forever, from disk, so they survive a cold start.
