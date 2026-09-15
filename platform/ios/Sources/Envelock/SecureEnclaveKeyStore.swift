import Foundation
import LocalAuthentication
import Security

/// The iOS half of envelock's security floor (spec 6.2, 7.2).
///
/// A P-256 key is generated inside the Secure Enclave and never leaves it. At enrollment a
/// random 32-byte device secret is sealed *to* that key's public half; every unlock decrypts it
/// with the private half, which the OS gates behind biometrics or the device passcode. That
/// prompt is the single prompt of a steady-state unlock.
///
/// ## This file performs no key derivation
///
/// It unseals bytes and hands them over. The core HKDFs them with a domain-separated string.
/// If this file derived instead, the same logic would have to exist in Kotlin too, and one of
/// them would eventually differ by a byte - leaving a user who restored onto the other platform
/// unable to decrypt (spec 3.2). Everything here is key management and nothing else.
///
/// ## `.userPresence`, not `.biometryCurrentSet`
///
/// `.biometryCurrentSet` invalidates the key the moment the user enrolls a new fingerprint or
/// re-registers Face ID - spontaneous data loss for an entirely benign action.
/// `.userPresence` accepts biometrics *or* the device passcode and survives enrollment changes.
/// The recovery path, not enclave invalidation, is the right answer to a credential change
/// (spec 6.2).
///
/// ## Why ECIES rather than the spec's hand-rolled ECDH
///
/// Spec 6.2 describes deriving via ECDH against a stored ephemeral public key, then HKDF-ing
/// the shared secret. `eciesEncryptionCofactorX963SHA256AESGCM` is that construction - ECDH,
/// X9.63 KDF, AES-GCM - implemented by Apple. Same security property, and materially less
/// hand-written crypto in the one file that shared test vectors cannot cover.
public final class SecureEnclaveKeyStore: EnclaveKeyStoreFfi, @unchecked Sendable {

    public enum Failure: Error, LocalizedError {
        case secureEnclaveUnavailable
        case keyGeneration(String)
        case keyMissing
        case sealedSecretMissing
        case keychain(OSStatus)
        case cryptography(String)
        case userCancelled

        var asFfi: FfiVaultError {
            switch self {
            case .userCancelled:
                return .Cancelled
            case .cryptography(let m):
                return .CorruptData(detail: m)
            default:
                return .Misconfigured(detail: errorDescription ?? "\(self)")
            }
        }

        public var errorDescription: String? {
            switch self {
            case .secureEnclaveUnavailable:
                return "this device has no Secure Enclave"
            case .keyGeneration(let m): return "could not create the enclave key: \(m)"
            case .keyMissing: return "no enclave key exists for this vault"
            case .sealedSecretMissing: return "the sealed device secret is missing"
            case .keychain(let s): return "keychain error \(s)"
            case .cryptography(let m): return "cryptographic operation failed: \(m)"
            case .userCancelled: return "cancelled by the user"
            }
        }
    }

    private func mapped<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let failure as Failure {
            if case .userCancelled = failure {} else {
                print("[envelock] enclave failure: \(failure.errorDescription ?? "\(failure)")")
            }
            throw failure.asFfi
        }
    }

    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
    private static let secretLength = 32

    private let service: String
    private let accessGroup: String?
    private let reuseDuration: TimeInterval
    private let localizedReason: String

    private let stateLock = NSLock()
    private var reusableContext: LAContext?
    private var contextIssuedAt: Date?

    /// - Parameters:
    ///   - service: Keychain service and key-tag prefix. The consuming SDK sets this so two
    ///     SDKs in one app cannot collide.
    ///   - accessGroup: Keychain access group, for app-group or extension sharing.
    ///   - authenticationReuseDuration: How long one authentication covers subsequent
    ///     operations, so a burst does not prompt repeatedly. iOS caps this at 300 s (spec 6.2).
    ///   - localizedReason: Shown in the system prompt.
    public init(
        service: String,
        accessGroup: String? = nil,
        authenticationReuseDuration: TimeInterval = 60,
        localizedReason: String = "Unlock your secure data"
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.reuseDuration = min(max(authenticationReuseDuration, 0), 300)
        self.localizedReason = localizedReason
    }

    // MARK: - EnclaveKeyStoreFfi

    public func createKey(vaultId: Data) throws {
        try mapped { try createKeyUnmapped(vaultId: vaultId) }
    }

    private func createKeyUnmapped(vaultId: Data) throws {
        guard Self.isSecureEnclaveAvailable else { throw Failure.secureEnclaveUnavailable }

        // Idempotent: enrollment may be retried after a transient failure, and regenerating
        // would orphan the sealed secret and with it the user's data.
        if (try? loadPrivateKey(vaultId: vaultId, context: nil)) != nil,
           (try? loadSealedSecret(vaultId: vaultId)) != nil {
            return
        }

        deleteKeychainItems(vaultId: vaultId)

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else {
            throw Failure.keyGeneration(Self.describe(accessError))
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(for: vaultId),
                kSecAttrAccessControl as String: access,
            ],
        ]

        var createError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) else {
            throw Failure.keyGeneration(Self.describe(createError))
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw Failure.keyGeneration("could not read the public key")
        }

        // Sealing uses the public half only, so this step raises no prompt. The user is asked
        // for consent once, when the key itself is created.
        var secret = Data(count: Self.secretLength)
        let status = secret.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, Self.secretLength, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
        defer { secret.resetBytes(in: 0..<secret.count) }

        var sealError: Unmanaged<CFError>?
        guard let sealed = SecKeyCreateEncryptedData(
            publicKey, Self.algorithm, secret as CFData, &sealError
        ) as Data? else {
            throw Failure.cryptography(Self.describe(sealError))
        }

        try storeSealedSecret(sealed, vaultId: vaultId)
    }

    public func deviceSecret(vaultId: Data) throws -> Data {
        try mapped { try deviceSecretUnmapped(vaultId: vaultId) }
    }

    private func deviceSecretUnmapped(vaultId: Data) throws -> Data {
        let context = authenticationContext()
        let privateKey = try loadPrivateKey(vaultId: vaultId, context: context)
        let sealed = try loadSealedSecret(vaultId: vaultId)

        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey, Self.algorithm, sealed as CFData, &error
        ) as Data? else {
            throw Self.mapDecryptionFailure(error)
        }

        guard plaintext.count == Self.secretLength else {
            throw Failure.cryptography("unsealed \(plaintext.count) bytes, expected \(Self.secretLength)")
        }
        return plaintext
    }

    public func keyExists(vaultId: Data) throws -> Bool {
        try mapped { try keyExistsUnmapped(vaultId: vaultId) }
    }

    private func keyExistsUnmapped(vaultId: Data) throws -> Bool {
        // Deliberately does not authenticate: this is a status query, and it is called from
        // `state()`, which must never raise a biometric prompt. `kSecUseAuthenticationUISkip`
        // asks the keychain for the item's presence without trying to use it.
        var query = baseKeyQuery(vaultId: vaultId)
        query[kSecReturnRef as String] = false
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip

        let keyStatus = SecItemCopyMatching(query as CFDictionary, nil)
        let keyPresent = keyStatus == errSecSuccess || keyStatus == errSecInteractionNotAllowed
        return keyPresent && (try? loadSealedSecret(vaultId: vaultId)) != nil
    }

    public func deleteKey(vaultId: Data) throws {
        try mapped {
            deleteKeychainItems(vaultId: vaultId)
            invalidateContext()
        }
    }

    public func hardwareBacking() -> FfiHardwareBacking {
        // Reported truthfully. A simulator or a device without an enclave says `software`, and
        // the docs state plainly that the spec 2.3 floor does not hold there (spec 6.4).
        Self.isSecureEnclaveAvailable ? .secureEnclave : .software
    }

    // MARK: - Lifecycle

    /// Drop any cached authentication. Call alongside `vault.lock()` when the app backgrounds,
    /// so returning to the foreground re-authenticates.
    public func invalidateContext() {
        stateLock.lock()
        defer { stateLock.unlock() }
        reusableContext?.invalidate()
        reusableContext = nil
        contextIssuedAt = nil
    }

    // MARK: - Internals

    private static var isSecureEnclaveAvailable: Bool {
        #if targetEnvironment(simulator)
        // The Simulator has no Secure Enclave. Reporting `secureEnclave` here would make every
        // simulator run claim a security posture the device does not have.
        return false
        #else
        return true
        #endif
    }

    /// One `LAContext` reused for `reuseDuration`, so a burst of operations costs one prompt
    /// rather than one prompt each (spec 6.2).
    private func authenticationContext() -> LAContext {
        stateLock.lock()
        defer { stateLock.unlock() }

        if let existing = reusableContext,
           let issued = contextIssuedAt,
           Date().timeIntervalSince(issued) < reuseDuration {
            return existing
        }

        reusableContext?.invalidate()
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = reuseDuration
        context.localizedReason = localizedReason
        reusableContext = context
        contextIssuedAt = Date()
        return context
    }

    private func tag(for vaultId: Data) -> Data {
        Data("\(service).key.\(vaultId.hexString)".utf8)
    }

    private func account(for vaultId: Data) -> String {
        "\(service).sealed.\(vaultId.hexString)"
    }

    private func baseKeyQuery(vaultId: Data) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag(for: vaultId),
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    private func loadPrivateKey(vaultId: Data, context: LAContext?) throws -> SecKey {
        var query = baseKeyQuery(vaultId: vaultId)
        query[kSecReturnRef as String] = true
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
                throw Failure.keyMissing
            }
            return unsafeDowncast(item as AnyObject, to: SecKey.self)
        case errSecItemNotFound:
            throw Failure.keyMissing
        case errSecUserCanceled:
            throw Failure.userCancelled
        default:
            throw Failure.keychain(status)
        }
    }

    private func storeSealedSecret(_ sealed: Data, vaultId: Data) throws {
        var item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: vaultId),
            kSecValueData as String: sealed,
            // `ThisDeviceOnly` keeps the item out of iCloud Keychain. Migrating it would leave
            // a dangling reference on the new device, since the enclave key cannot follow
            // (spec 5.3).
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        if let accessGroup { item[kSecAttrAccessGroup as String] = accessGroup }

        SecItemDelete(item as CFDictionary)
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }

    private func loadSealedSecret(vaultId: Data) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: vaultId),
            kSecReturnData as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw status == errSecItemNotFound
                ? Failure.sealedSecretMissing
                : Failure.keychain(status)
        }
        return data
    }

    private func deleteKeychainItems(vaultId: Data) {
        var keyQuery = baseKeyQuery(vaultId: vaultId)
        keyQuery[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        SecItemDelete(keyQuery as CFDictionary)

        var secretQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(for: vaultId),
        ]
        if let accessGroup { secretQuery[kSecAttrAccessGroup as String] = accessGroup }
        SecItemDelete(secretQuery as CFDictionary)
    }

    /// A dismissed prompt must surface as `Cancelled`, never as a denial - spec 7.4 counts
    /// only genuine denials toward lockout, and cancelling is normal user behaviour.
    private static func mapDecryptionFailure(_ error: Unmanaged<CFError>?) -> Failure {
        guard let cf = error?.takeRetainedValue() else {
            return .cryptography("unknown failure")
        }
        let nsError = cf as Error as NSError
        let cancelCodes: Set<Int> = [
            LAError.userCancel.rawValue,
            LAError.appCancel.rawValue,
            LAError.systemCancel.rawValue,
        ]
        if nsError.domain == LAError.errorDomain && cancelCodes.contains(nsError.code) {
            return .userCancelled
        }
        if nsError.code == Int(errSecUserCanceled) { return .userCancelled }
        return .cryptography(nsError.localizedDescription)
    }

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let cf = error?.takeRetainedValue() else { return "unknown error" }
        return (cf as Error).localizedDescription
    }
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
