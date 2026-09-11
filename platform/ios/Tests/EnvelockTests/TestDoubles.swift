import Foundation
@testable import EnvelockCore

// Test doubles for the collaborators a vault requires.
//
// `SoftwareKeyStore` lives in the test target and nowhere else. Spec 7.2 requires that no
// configuration flag, debug option or test hook can disable the enclave factor in a shipped
// build; keeping the software stand-in out of `Sources/` is how that holds on this side of the
// bridge, mirroring `#[cfg(test)]` on the Rust side.

/// In-memory stand-in for the Secure Enclave, so the bridge can be exercised on a simulator.
///
/// Constructing a fresh instance models a *different device*, which is how the recovery path
/// gets tested.
final class SoftwareKeyStore: EnclaveKeyStoreFfi, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [Data: Data] = [:]

    /// When set, `deviceSecret` throws it - a dismissed biometric prompt.
    var denyWith: FfiVaultError?

    func createKey(vaultId: Data) throws {
        lock.lock(); defer { lock.unlock() }
        guard keys[vaultId] == nil else { return }
        var bytes = Data(count: 32)
        _ = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        keys[vaultId] = bytes
    }

    func deviceSecret(vaultId: Data) throws -> Data {
        if let denyWith { throw denyWith }
        lock.lock(); defer { lock.unlock() }
        guard let key = keys[vaultId] else {
            throw FfiVaultError.Misconfigured(detail: "no enclave key")
        }
        return key
    }

    func keyExists(vaultId: Data) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        return keys[vaultId] != nil
    }

    func deleteKey(vaultId: Data) throws {
        lock.lock(); defer { lock.unlock() }
        keys[vaultId] = nil
    }

    func hardwareBacking() -> FfiHardwareBacking { .software }

    func wipe() {
        lock.lock(); defer { lock.unlock() }
        keys.removeAll()
    }
}

/// A scriptable `getKeyMaterial`.
final class ScriptedMaterial: KeyMaterialProviderFfi, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls = 0

    var material: Data = ScriptedMaterial.good
    var keyId: String = "v1"
    var cacheable: Bool = true
    var cacheTtlMs: UInt64 = 30 * 24 * 60 * 60 * 1000
    var failWith: FfiVaultError?
    /// Sleep this long, to exercise the deadline envelock enforces.
    var hangMs: UInt64 = 0

    /// 32 bytes that pass enrollment validation.
    static let good = Data((0..<32).map { UInt8(($0 &* 37 &+ 11) % 256) })

    var calls: Int {
        lock.lock(); defer { lock.unlock() }
        return _calls
    }

    func resetCalls() {
        lock.lock(); defer { lock.unlock() }
        _calls = 0
    }

    func getKeyMaterial(ctx: FfiMaterialContext) throws -> FfiKeyMaterial {
        lock.lock(); _calls += 1; lock.unlock()

        if hangMs > 0 { Thread.sleep(forTimeInterval: Double(hangMs) / 1000.0) }
        if let failWith { throw failWith }

        return FfiKeyMaterial(
            material: material,
            keyId: keyId,
            cacheable: cacheable,
            cacheTtlMs: cacheTtlMs
        )
    }
}

final class ScriptedRecovery: RecoveryProviderFfi, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls = 0
    private var _factor: FfiRecoveryFactor
    private(set) var lastReason: FfiRecoveryReason?

    init(_ factor: FfiRecoveryFactor) { self._factor = factor }

    var calls: Int {
        lock.lock(); defer { lock.unlock() }
        return _calls
    }

    func set(_ factor: FfiRecoveryFactor) {
        lock.lock(); defer { lock.unlock() }
        _factor = factor
    }

    func getRecoveryFactor(reason: FfiRecoveryReason) throws -> FfiRecoveryFactor {
        lock.lock(); defer { lock.unlock() }
        _calls += 1
        lastReason = reason
        return _factor
    }
}

final class EventLog: SecurityEventSinkFfi, @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [FfiSecurityEvent] = []

    var events: [FfiSecurityEvent] {
        lock.lock(); defer { lock.unlock() }
        return _events
    }

    func onEvent(event: FfiSecurityEvent) {
        lock.lock(); defer { lock.unlock() }
        _events.append(event)
    }
}

/// A temporary directory removed when the test finishes.
final class TempDir {
    let url: URL

    init() {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("envelock-swift-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: url) }
}

func bip85Factor(_ byte: UInt8) -> FfiRecoveryFactor {
    .highEntropy(bytes: Data(repeating: byte, count: 32))
}
