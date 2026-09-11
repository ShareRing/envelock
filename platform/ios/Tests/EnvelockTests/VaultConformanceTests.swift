import XCTest
@testable import EnvelockCore

/// Bridge conformance: does the Swift side of the FFI behave like the Rust side?
///
/// ## Why this suite does not re-run `vectors.json`
///
/// Spec 13.1 has every binding check the shared vectors, and that is right for a binding that
/// *reimplements* derivation. These bindings do not - they call the same Rust core, so a Swift
/// run of the vectors would only be testing Rust through a bridge. `vectors.json` remains the
/// contract for anyone reimplementing envelock in another language, and it is enforced in
/// `core/tests/vectors.rs`.
///
/// What can genuinely go wrong here is the bridge: a mis-mapped error variant that turns a
/// cancelled prompt into a lockout-counting denial, a byte array truncated in conversion, a
/// callback invoked more than once. That is what this suite covers.
final class VaultConformanceTests: XCTestCase {

    private var tmp: TempDir!
    private var enclave: SoftwareKeyStore!
    private var material: ScriptedMaterial!
    private var recovery: ScriptedRecovery!
    private var events: EventLog!

    override func setUp() {
        super.setUp()
        tmp = TempDir()
        enclave = SoftwareKeyStore()
        material = ScriptedMaterial()
        recovery = ScriptedRecovery(bip85Factor(0x5a))
        events = EventLog()
    }

    private func makeVault(
        enclave override: SoftwareKeyStore? = nil,
        configure: ((inout FfiVaultConfig) -> Void)? = nil
    ) throws -> FfiVault {
        var config = defaultConfig(providerId: "test-provider", dir: tmp.url.path)
        config.argon2MKib = 8 * 1024
        config.argon2T = 1
        configure?(&config)

        return try FfiVault(
            config: config,
            enclave: override ?? enclave,
            material: material,
            recovery: recovery,
            events: events
        )
    }

    // MARK: - Happy path

    func testEnrollThenReadAndWrite() throws {
        let vault = try makeVault()
        XCTAssertEqual(vault.state(), .notEnrolled)

        try vault.enroll(factor: bip85Factor(0x5a))
        XCTAssertEqual(vault.state(), .unlocked)

        try vault.put(recordId: "card:1", plaintext: Data("balance:100".utf8))
        XCTAssertEqual(try vault.get(recordId: "card:1"), Data("balance:100".utf8))
        XCTAssertEqual(try vault.list(prefix: "card:"), ["card:1"])

        try vault.delete(recordId: "card:1")
        XCTAssertNil(try vault.get(recordId: "card:1"))
    }

    /// Spec 8.2: a steady-state unlock reads cached material, so the callback does not fire.
    func testUnlockAfterRestartIsOfflineAndPromptsOnce() throws {
        try makeVault().enroll(factor: bip85Factor(0x5a))
        XCTAssertEqual(material.calls, 1, "one fetch at enrollment")

        material.resetCalls()
        let vault = try makeVault()
        XCTAssertEqual(vault.state(), .locked)

        try vault.unlock()
        XCTAssertEqual(vault.state(), .unlocked)
        XCTAssertEqual(material.calls, 0, "unlock must work offline")
    }

    func testRecordsSurviveARestart() throws {
        let first = try makeVault()
        try first.enroll(factor: bip85Factor(0x5a))
        try first.put(recordId: "card:1", plaintext: Data("balance:100".utf8))

        let second = try makeVault()
        try second.unlock()
        XCTAssertEqual(try second.get(recordId: "card:1"), Data("balance:100".utf8))
    }

    func testLockedVaultRefusesRecordAccess() throws {
        let vault = try makeVault()
        try vault.enroll(factor: bip85Factor(0x5a))
        try vault.put(recordId: "card:1", plaintext: Data("x".utf8))

        vault.lock()
        XCTAssertEqual(vault.state(), .locked)
        XCTAssertThrowsError(try vault.get(recordId: "card:1"))
    }

    // MARK: - Error taxonomy across the bridge (spec 7.4)

    /// The mapping that matters most: a Swift provider throwing `.cancelled` must not arrive as
    /// something that counts toward lockout.
    func testEachRejectionTypeCrossesTheBridgeIntact() throws {
        let cases: [(FfiVaultError, String)] = [
            (.Cancelled, "cancelled"),
            (.Unavailable, "unavailable"),
            (.Denied, "denied"),
            (.Misconfigured(detail: "bug"), "misconfigured"),
        ]

        for (thrown, label) in cases {
            let dir = TempDir()
            material.failWith = thrown

            var config = defaultConfig(providerId: "test-provider", dir: dir.url.path)
            config.argon2MKib = 8 * 1024
            let vault = try FfiVault(
                config: config,
                enclave: SoftwareKeyStore(),
                material: material,
                recovery: recovery,
                events: events
            )

            XCTAssertThrowsError(try vault.enroll(factor: bip85Factor(0x5a)), label) { error in
                switch (error as? FfiVaultError, thrown) {
                case (.Cancelled, .Cancelled), (.Unavailable, .Unavailable),
                     (.Denied, .Denied), (.Misconfigured, .Misconfigured):
                    break
                default:
                    XCTFail("\(label): expected \(thrown), got \(error)")
                }
            }
        }
    }

    /// A flaky network must never look like a failed authentication. An unrecognised Swift
    /// error becomes `unavailable`: retryable and uncounted - not `denied`.
    func testUnrecognisedSwiftErrorBecomesUnavailable() throws {
        struct SomeNetworkError: Swift.Error {}

        final class ThrowingProvider: KeyMaterialProviderFfi, @unchecked Sendable {
            func getKeyMaterial(ctx: FfiMaterialContext) throws -> FfiKeyMaterial {
                throw SomeNetworkError()
            }
        }

        var config = defaultConfig(providerId: "test-provider", dir: tmp.url.path)
        config.argon2MKib = 8 * 1024
        let vault = try FfiVault(
            config: config,
            enclave: enclave,
            material: ThrowingProvider(),
            recovery: recovery,
            events: events
        )

        XCTAssertThrowsError(try vault.enroll(factor: bip85Factor(0x5a))) { error in
            guard case .Unavailable? = error as? FfiVaultError else {
                return XCTFail("expected .Unavailable, got \(error)")
            }
        }
    }

    /// Spec 7.5: a nondeterministic callback must be reported as a mismatch, not as data
    /// corruption. This is the message an integrator will actually read.
    func testNondeterministicCallbackReportsAMismatch() throws {
        try makeVault().enroll(factor: bip85Factor(0x5a))

        material.material = Data(repeating: 0x77, count: 32)
        try? FileManager.default.removeItem(at: tmp.url.appendingPathComponent("material.cache"))

        let vault = try makeVault()
        XCTAssertThrowsError(try vault.unlock()) { error in
            guard case .ProviderMaterialMismatch(let message)? = error as? FfiVaultError else {
                return XCTFail("expected .ProviderMaterialMismatch, got \(error)")
            }
            XCTAssertTrue(message.contains("deterministic"))
            XCTAssertTrue(message.contains("PROVIDERS.md"))
        }
    }

    func testBadMaterialIsRejectedAtEnrollment() throws {
        for bad in [Data(repeating: 0, count: 32),
                    Data(repeating: 0xAB, count: 32),
                    Data(repeating: 7, count: 31)] {
            let dir = TempDir()
            material.material = bad

            var config = defaultConfig(providerId: "test-provider", dir: dir.url.path)
            config.argon2MKib = 8 * 1024
            let vault = try FfiVault(
                config: config,
                enclave: SoftwareKeyStore(),
                material: material,
                recovery: recovery,
                events: events
            )

            XCTAssertThrowsError(try vault.enroll(factor: bip85Factor(0x5a))) { error in
                guard case .MaterialRejected? = error as? FfiVaultError else {
                    return XCTFail("expected .MaterialRejected, got \(error)")
                }
            }
        }
    }

    /// envelock enforces the deadline itself, so a hung Swift callback cannot hang the caller
    /// indefinitely (spec 7.4).
    func testHungCallbackTimesOut() throws {
        material.hangMs = 30_000
        let vault = try makeVault { $0.callbackDeadlineMs = 200 }

        let started = Date()
        XCTAssertThrowsError(try vault.enroll(factor: bip85Factor(0x5a))) { error in
            guard case .Unavailable? = error as? FfiVaultError else {
                return XCTFail("expected .Unavailable, got \(error)")
            }
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
    }

    /// Spec 11.3: concurrent unlocks coalesce into exactly one callback invocation.
    func testConcurrentUnlocksInvokeTheCallbackOnce() throws {
        try makeVault().enroll(factor: bip85Factor(0x5a))
        try? FileManager.default.removeItem(at: tmp.url.appendingPathComponent("material.cache"))
        material.resetCalls()

        let vault = try makeVault()
        let group = DispatchGroup()
        for _ in 0..<8 {
            group.enter()
            DispatchQueue.global().async {
                try? vault.unlock()
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)

        XCTAssertEqual(material.calls, 1)
        XCTAssertEqual(vault.state(), .unlocked)
    }

    // MARK: - Recovery (spec 8.4)

    func testRecoveryOnANewDeviceRewrapsThePrimaryPath() throws {
        let first = try makeVault()
        try first.enroll(factor: bip85Factor(0x5a))
        try first.put(recordId: "card:1", plaintext: Data("balance:100".utf8))

        // A restored backup on hardware that has never seen this vault.
        let freshEnclave = SoftwareKeyStore()
        let vault = try makeVault(enclave: freshEnclave)
        XCTAssertEqual(vault.state(), .needsRecovery)

        try vault.unlockWithRecovery()
        XCTAssertEqual(vault.state(), .unlocked)
        XCTAssertEqual(try vault.get(recordId: "card:1"), Data("balance:100".utf8))
        XCTAssertEqual(recovery.lastReason, .migrate)

        // The mandatory rewrap means the next unlock takes the primary path with no recovery
        // prompt - otherwise the user would re-enter their factor forever.
        let recoveryCallsBefore = recovery.calls
        vault.lock()
        try vault.unlock()
        XCTAssertEqual(recovery.calls, recoveryCallsBefore)
    }

    func testMissingEnclaveKeyIsNeedsRecoveryNotACrash() throws {
        let vault = try makeVault()
        try vault.enroll(factor: bip85Factor(0x5a))

        enclave.wipe()
        let reopened = try makeVault()
        XCTAssertEqual(reopened.state(), .needsRecovery)
    }

    func testWrongRecoveryFactorIsDenied() throws {
        try makeVault().enroll(factor: bip85Factor(0x5a))
        recovery.set(bip85Factor(0xFF))

        let vault = try makeVault(enclave: SoftwareKeyStore())
        XCTAssertThrowsError(try vault.unlockWithRecovery()) { error in
            guard case .Denied? = error as? FfiVaultError else {
                return XCTFail("expected .Denied, got \(error)")
            }
        }
    }

    /// A high-entropy factor carries no attempt counter: 128 bits is not guessable, so wrong
    /// guesses neither lock out nor destroy (spec 10).
    func testHighEntropyVaultHasNoLockout() throws {
        try makeVault().enroll(factor: bip85Factor(0x5a))
        recovery.set(bip85Factor(0xFF))
        let vault = try makeVault(enclave: SoftwareKeyStore())

        for _ in 0..<15 {
            XCTAssertThrowsError(try vault.unlockWithRecovery())
        }

        recovery.set(bip85Factor(0x5a))
        try vault.unlockWithRecovery()
        XCTAssertEqual(vault.state(), .unlocked)
    }

    func testHighEntropyFactorMustBeExactlyThirtyTwoBytes() throws {
        let vault = try makeVault()
        for length in [0, 16, 31, 33] {
            let factor = FfiRecoveryFactor.highEntropy(bytes: Data(repeating: 1, count: length))
            XCTAssertThrowsError(try vault.enroll(factor: factor), "\(length) bytes")
        }
    }

    // MARK: - Lifecycle

    func testDestroyRemovesEverything() throws {
        let vault = try makeVault()
        try vault.enroll(factor: bip85Factor(0x5a))
        try vault.put(recordId: "card:1", plaintext: Data("x".utf8))

        try vault.destroyVault()
        XCTAssertEqual(vault.state(), .notEnrolled)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: tmp.url.appendingPathComponent("envelope.cbor").path)
        )
    }

    func testSecurityInfoReportsBackingTruthfully() throws {
        let vault = try makeVault()
        try vault.enroll(factor: bip85Factor(0x5a))

        let info = try vault.securityInfo()
        // The double is software-backed and must say so rather than flattering the device.
        XCTAssertEqual(info.hardwareBacking, .software)
        XCTAssertFalse(info.hardwareBacking.isHardwareBacked)
        XCTAssertEqual(info.providerId, "test-provider")
        XCTAssertEqual(info.keyId, "v1")
        XCTAssertEqual(info.recoveryKind, .highEntropy)
        XCTAssertEqual(info.failedAttempts, 0)
    }

    func testSchemeVersionIsExposed() {
        XCTAssertEqual(Envelock.derivationSchemeVersion, 1)
    }
}
