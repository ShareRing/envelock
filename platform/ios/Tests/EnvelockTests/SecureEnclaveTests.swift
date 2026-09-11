import XCTest
@testable import EnvelockCore

/// Exercises the real Secure Enclave.
///
/// **These require a physical device.** The Simulator has no Secure Enclave, so
/// `SecAttrTokenIDSecureEnclave` key creation fails there. Every test below skips itself rather
/// than failing, so a simulator CI run stays green while still reporting what it could not
/// cover - a silently-skipped hardware test is how a broken shim reaches production.
///
/// Running them prompts for biometrics or the device passcode, so they cannot run unattended.
final class SecureEnclaveTests: XCTestCase {

    private var store: SecureEnclaveKeyStore!
    private var vaultId: Data!

    override func setUpWithError() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("The Simulator has no Secure Enclave; run on a physical device.")
        #else
        store = SecureEnclaveKeyStore(
            service: "network.sharering.envelock.tests",
            authenticationReuseDuration: 300
        )
        vaultId = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        #endif
    }

    override func tearDownWithError() throws {
        try? store?.deleteKey(vaultId: vaultId)
    }

    func testReportsSecureEnclaveBackingOnDevice() throws {
        XCTAssertEqual(store.hardwareBacking(), .secureEnclave)
        XCTAssertTrue(store.hardwareBacking().isHardwareBacked)
    }

    func testCreateThenUnsealTheDeviceSecret() throws {
        XCTAssertFalse(try store.keyExists(vaultId: vaultId))

        try store.createKey(vaultId: vaultId)
        XCTAssertTrue(try store.keyExists(vaultId: vaultId))

        let secret = try store.deviceSecret(vaultId: vaultId)
        XCTAssertEqual(secret.count, 32)
        XCTAssertNotEqual(secret, Data(repeating: 0, count: 32))

        // Stable across calls: the whole key hierarchy depends on it.
        XCTAssertEqual(try store.deviceSecret(vaultId: vaultId), secret)
    }

    /// `keyExists` is called from `state()`, which must never raise a biometric prompt just to
    /// answer a status query.
    func testKeyExistsDoesNotPrompt() throws {
        try store.createKey(vaultId: vaultId)
        store.invalidateContext()
        for _ in 0..<5 {
            XCTAssertTrue(try store.keyExists(vaultId: vaultId))
        }
    }

    /// Creating twice must be a no-op. Regenerating would orphan the sealed secret, and with it
    /// the user's data.
    func testCreateKeyIsIdempotent() throws {
        try store.createKey(vaultId: vaultId)
        let first = try store.deviceSecret(vaultId: vaultId)

        try store.createKey(vaultId: vaultId)
        XCTAssertEqual(try store.deviceSecret(vaultId: vaultId), first)
    }

    func testDeleteRemovesBothTheKeyAndTheSealedSecret() throws {
        try store.createKey(vaultId: vaultId)
        try store.deleteKey(vaultId: vaultId)

        XCTAssertFalse(try store.keyExists(vaultId: vaultId))
        XCTAssertThrowsError(try store.deviceSecret(vaultId: vaultId))
    }

    func testVaultsAreIsolated() throws {
        let other = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        defer { try? store.deleteKey(vaultId: other) }

        try store.createKey(vaultId: vaultId)
        try store.createKey(vaultId: other)

        XCTAssertNotEqual(
            try store.deviceSecret(vaultId: vaultId),
            try store.deviceSecret(vaultId: other)
        )
    }

    /// A full enroll -> lock -> unlock -> read cycle against real hardware.
    func testEndToEndAgainstRealHardware() throws {
        let tmp = TempDir()
        let material = ScriptedMaterial()
        let recovery = ScriptedRecovery(bip85Factor(0x5a))

        var config = defaultConfig(providerId: "test-provider", dir: tmp.url.path)
        config.argon2MKib = 8 * 1024
        let vault = try FfiVault(
            config: config,
            enclave: store,
            material: material,
            recovery: recovery,
            events: nil
        )

        try vault.enroll(factor: bip85Factor(0x5a))
        try vault.put(recordId: "card:1", plaintext: Data("balance:100".utf8))

        vault.lock()
        XCTAssertEqual(vault.state(), .locked)

        material.resetCalls()
        try vault.unlock()
        XCTAssertEqual(try vault.get(recordId: "card:1"), Data("balance:100".utf8))
        XCTAssertEqual(material.calls, 0, "the cached material makes unlock offline")

        let info = try vault.securityInfo()
        XCTAssertEqual(info.hardwareBacking, .secureEnclave)

        try vault.destroyVault()
    }

    /// Regression test for the `.userPresence` choice (spec 6.2, 13.2).
    ///
    /// `.biometryCurrentSet` would invalidate the key the moment a fingerprint is enrolled,
    /// destroying the user's data for an entirely benign action. This cannot be automated -
    /// enroll a new fingerprint or re-register Face ID between the two runs described below.
    func testSurvivesBiometricEnrollmentChange() throws {
        throw XCTSkip("""
            Manual: run `testCreateThenUnsealTheDeviceSecret` on a device and note the secret; \
            add a fingerprint or re-register Face ID; run it again against the same vaultId and \
            confirm the secret is unchanged and no re-enrollment was required.
            """)
    }
}
