import Foundation

/// envelock on iOS.
///
/// The generated UniFFI types carry `Ffi` prefixes because they are the bridge's own shapes.
/// These aliases give the consuming SDK names worth reading; they are aliases, not wrappers, so
/// nothing is copied and nothing can drift.
public enum Envelock {
    public typealias Vault = FfiVault
    public typealias Config = FfiVaultConfig
    public typealias State = FfiVaultState
    public typealias Error = FfiVaultError
    public typealias RecoveryFactor = FfiRecoveryFactor
    public typealias RecoveryReason = FfiRecoveryReason
    public typealias MaterialContext = FfiMaterialContext
    public typealias MaterialReason = FfiMaterialReason
    public typealias KeyMaterial = FfiKeyMaterial
    public typealias SecurityInfo = FfiSecurityInfo
    public typealias SecurityEvent = FfiSecurityEvent
    public typealias HardwareBacking = FfiHardwareBacking
    public typealias RecoveryKind = FfiRecoveryKind

    public typealias KeyMaterialProvider = KeyMaterialProviderFfi
    public typealias RecoveryProvider = RecoveryProviderFfi
    public typealias SecurityEventSink = SecurityEventSinkFfi
    public typealias EnclaveKeyStore = EnclaveKeyStoreFfi

    /// Derivation scheme version this build writes (spec 14). Not the package version.
    public static var derivationSchemeVersion: UInt16 { schemeVersion() }

    /// Build a vault backed by the Secure Enclave.
    ///
    /// - Parameters:
    ///   - providerId: Stable identifier namespaced into derivation. **Changing it invalidates
    ///     every existing vault**, so pick it once.
    ///   - directory: An app-private directory. Use Application Support, not Caches - the OS
    ///     evicts Caches under pressure, which would destroy the envelope.
    ///   - material: Your `getKeyMaterial` implementation. Must return identical bytes for a
    ///     given key id, every call.
    ///   - recovery: Supplies the recovery factor. envelock ships no UI, so this is required.
    ///
    /// ## Lifecycle you must wire up
    ///
    /// On `applicationDidEnterBackground`, call `vault.lock()` and
    /// `keyStore.invalidateContext()`. Zeroization happens inside the Rust core; dropping a
    /// Swift reference gives no guarantee the key bytes ever leave memory (spec 11.3).
    public static func makeVault(
        providerId: String,
        directory: URL,
        keychainService: String,
        material: KeyMaterialProvider,
        recovery: RecoveryProvider,
        events: SecurityEventSink? = nil,
        accessGroup: String? = nil,
        configure: ((inout Config) -> Void)? = nil
    ) throws -> (vault: Vault, keyStore: SecureEnclaveKeyStore) {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )

        var config = defaultConfig(providerId: providerId, dir: directory.path)
        configure?(&config)

        let keyStore = SecureEnclaveKeyStore(service: keychainService, accessGroup: accessGroup)
        let vault = try Vault(
            config: config,
            enclave: keyStore,
            material: material,
            recovery: recovery,
            events: events
        )
        return (vault, keyStore)
    }
}

public extension FfiRecoveryFactor {
    /// A 32-byte high-entropy factor - a BIP-85 child key derived from the wallet seed, or any
    /// 32 uniformly random bytes. No attempt limiting applies, because 128 bits is not
    /// guessable.
    static func highEntropy(_ bytes: Data) -> FfiRecoveryFactor {
        .highEntropy(bytes: bytes)
    }

    /// A user-chosen passphrase. Argon2id stretches it and the spec 10 backoff ladder applies.
    ///
    /// This is **not** the host app's PIN. envelock never receives, requests or stores a host
    /// credential (spec 0).
    static func passphrase(_ value: String) -> FfiRecoveryFactor {
        .passphrase(value: value)
    }
}

public extension FfiHardwareBacking {
    /// Whether the spec 2.3 security floor actually holds on this device.
    var isHardwareBacked: Bool { self != .software }
}
