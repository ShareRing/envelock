import EnvelockCore
import Flutter
import Foundation

/// The Flutter plugin.
///
/// ## How a synchronous Rust callback reaches an asynchronous Dart function
///
/// The Rust core calls `getKeyMaterial` and waits; a Dart provider returns a `Future`.
///
/// 1. Every vault method runs on a background queue, so the platform thread is never blocked.
/// 2. When Rust needs material, the native provider dispatches the Pigeon call to the main
///    thread (platform channels may only be used there) and blocks *its own* background thread
///    on a semaphore.
/// 3. Dart runs the callback and calls `resolveCallback(requestId, ...)`.
/// 4. The semaphore is signalled and the Rust call returns.
///
/// This cannot deadlock, because step 1 moved the work off the main thread. Blocking the main
/// thread in step 2 would deadlock at once: the thread that has to deliver Dart's answer would
/// be the one waiting for it.
public class EnvelockPlugin: NSObject, FlutterPlugin, EnvelockHostApi {

    private let queue = DispatchQueue(label: "network.sharering.envelock.flutter", attributes: .concurrent)
    private let pending = PendingCallbacks()

    private let registry = NSLock()
    private var vaults: [String: FfiVault] = [:]
    private var keyStores: [String: SecureEnclaveKeyStore] = [:]
    fileprivate var flutterApi: EnvelockFlutterApi?

    public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
        disposeAll()
        flutterApi = nil
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = EnvelockPlugin()
        instance.flutterApi = EnvelockFlutterApi(binaryMessenger: registrar.messenger())
        EnvelockHostApiSetup.setUp(binaryMessenger: registrar.messenger(), api: instance)
        registrar.publish(instance)
    }

    // MARK: - Lifecycle

    func create(
        config: WireVaultConfig,
        completion: @escaping (Result<WireVaultHandle, Error>) -> Void
    ) {
        queue.async {
            do {
                let directory = try self.resolveDirectory(config.directory)

                var vaultConfig = defaultConfig(providerId: config.providerId, dir: directory.path)
                vaultConfig.autoLockMs = UInt64(config.autoLockMs)
                vaultConfig.callbackDeadlineMs = UInt64(config.callbackDeadlineMs)
                vaultConfig.destroyAfterAttempts = config.destroyAfterAttempts.map(UInt32.init)

                let store = SecureEnclaveKeyStore(
                    service: "network.sharering.envelock.\(config.providerId)"
                )
                let vaultId = UUID().uuidString
                let vault = try FfiVault(
                    config: vaultConfig,
                    enclave: store,
                    material: BridgedMaterialProvider(plugin: self, vaultId: vaultId),
                    recovery: BridgedRecoveryProvider(plugin: self, vaultId: vaultId),
                    events: BridgedEventSink(plugin: self, vaultId: vaultId)
                )
                self.registry.lock()
                self.vaults[vaultId] = vault
                self.keyStores[vaultId] = store
                self.registry.unlock()
                completion(.success(
                    WireVaultHandle(vaultId: vaultId, directory: directory.path)
                ))
            } catch {
                completion(.failure(Self.flutterError(error)))
            }
        }
    }

    func dispose(vaultId: String, completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            self.registry.lock()
            let vault = self.vaults.removeValue(forKey: vaultId)
            let store = self.keyStores.removeValue(forKey: vaultId)
            self.registry.unlock()

            vault?.lock()
            store?.invalidateContext()
            // Waiters belonging to *this* vault must be released, or their threads block until
            // timeout. Other vaults' waiters are left alone: disposing one vault must not fail
            // a callback another one is still waiting on.
            self.pending.failAll(
                vaultId: vaultId,
                code: "unavailable",
                message: "the vault was disposed"
            )
            completion(.success(()))
        }
    }

    /// Release every vault. Called when the plugin itself goes away.
    func disposeAll() {
        registry.lock()
        let open = Array(vaults.values)
        let stores = Array(keyStores.values)
        vaults.removeAll()
        keyStores.removeAll()
        registry.unlock()

        for vault in open { vault.lock() }
        for store in stores { store.invalidateContext() }
        pending.failAllRemaining(code: "unavailable", message: "the plugin was torn down")
    }

    /// The vault named by `vaultId`, or nil once it has been disposed.
    private func vault(_ vaultId: String) -> FfiVault? {
        registry.lock()
        defer { registry.unlock() }
        return vaults[vaultId]
    }

    private func keyStore(_ vaultId: String) -> SecureEnclaveKeyStore? {
        registry.lock()
        defer { registry.unlock() }
        return keyStores[vaultId]
    }

    // MARK: - Vault operations

    func state(vaultId: String, completion: @escaping (Result<WireStateResult, Error>) -> Void) {
        run(vaultId, completion) { vault in
            switch vault.state() {
            case .notEnrolled: return WireStateResult(state: .notEnrolled)
            case .locked: return WireStateResult(state: .locked)
            case .unlocked: return WireStateResult(state: .unlocked)
            case .needsRecovery: return WireStateResult(state: .needsRecovery)
            case .lockedOut(let untilMs):
                return WireStateResult(state: .lockedOut, lockedUntilMs: Int64(untilMs))
            }
        }
    }

    func enroll(
        vaultId: String,
        factor: WireRecoveryFactor,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        run(vaultId, completion) { try $0.enroll(factor: Self.decodeFactor(factor)) }
    }

    func unlock(vaultId: String, completion: @escaping (Result<Void, Error>) -> Void) {
        run(vaultId, completion) { try $0.unlock() }
    }

    func unlockWithRecovery(
        vaultId: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        run(vaultId, completion) { try $0.unlockWithRecovery() }
    }

    func changeRecoveryFactor(
        vaultId: String,
        factor: WireRecoveryFactor,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        run(vaultId, completion) {
            try $0.changeRecoveryFactor(newFactor: Self.decodeFactor(factor))
        }
    }

    func put(
        vaultId: String,
        recordId: String,
        value: FlutterStandardTypedData,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        run(vaultId, completion) { try $0.put(recordId: recordId, plaintext: value.data) }
    }

    func get(
        vaultId: String,
        recordId: String,
        completion: @escaping (Result<FlutterStandardTypedData?, Error>) -> Void
    ) {
        run(vaultId, completion) { vault in
            try vault.get(recordId: recordId).map { FlutterStandardTypedData(bytes: $0) }
        }
    }

    func delete(
        vaultId: String,
        recordId: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        run(vaultId, completion) { try $0.delete(recordId: recordId) }
    }

    func list(
        vaultId: String,
        prefix: String,
        completion: @escaping (Result<[String], Error>) -> Void
    ) {
        run(vaultId, completion) { try $0.list(prefix: prefix) }
    }

    func lock(vaultId: String, completion: @escaping (Result<Void, Error>) -> Void) {
        run(vaultId, completion) { vault in
            vault.lock()
            // Drop cached authentication too, so returning to the foreground re-prompts.
            self.keyStore(vaultId)?.invalidateContext()
        }
    }

    func destroyVault(vaultId: String, completion: @escaping (Result<Void, Error>) -> Void) {
        run(vaultId, completion) { try $0.destroyVault() }
    }

    func securityInfo(
        vaultId: String,
        completion: @escaping (Result<WireSecurityInfo, Error>) -> Void
    ) {
        run(vaultId, completion) { vault in
            let i = try vault.securityInfo()
            return WireSecurityInfo(
                hardwareBacking: Self.wireBacking(i.hardwareBacking),
                providerId: i.providerId,
                keyId: i.keyId,
                recoveryKind: i.recoveryKind == .highEntropy ? .highEntropy : .passphrase,
                enrolledAt: Int64(i.enrolledAt),
                failedAttempts: Int64(i.failedAttempts),
                lockedUntil: Int64(i.lockedUntil),
                materialCachedUntil: i.materialCachedUntil.map { Int64($0) }
            )
        }
    }

    // MARK: - Callback plumbing

    func resolveCallback(
        requestId: String,
        payload: FlutterStandardTypedData?,
        payloadText: String?,
        errorCode: WireErrorCode?,
        errorMessage: String?
    ) throws {
        pending.resolve(
            requestId,
            bytes: payload?.data,
            text: payloadText,
            error: errorCode.map { (Self.codeName($0), errorMessage ?? "") }
        )
    }

    /// Ask Dart for something and block this (background) thread until it answers.
    fileprivate func askDart(
        vaultId: String,
        deadlineMs: UInt64,
        _ send: @escaping (EnvelockFlutterApi, String) -> Void
    ) throws -> (bytes: Data?, text: String?) {
        guard let api = flutterApi else {
            throw FfiVaultError.Misconfigured(detail: "the plugin is not registered")
        }

        let requestId = UUID().uuidString
        let waiter = pending.register(requestId, vaultId: vaultId)

        // Platform channels are main-thread only. This must be `async`, never `sync`: the
        // caller is a background thread, and the main thread is the one that will deliver the
        // answer.
        DispatchQueue.main.async { send(api, requestId) }

        // A generous margin over envelock's own deadline; the core is the authority on timing.
        do {
            return try waiter.wait(timeoutMs: deadlineMs + 5_000)
        } catch {
            print(
                "[envelock] provider callback \(requestId) did not answer within "
                    + "\(deadlineMs + 5_000)ms; envelock reports this as `unavailable`"
            )
            throw error
        }
    }

    // MARK: - Helpers

    private func run<T>(
        _ vaultId: String,
        _ completion: @escaping (Result<T, Error>) -> Void,
        _ body: @escaping (FfiVault) throws -> T
    ) {
        queue.async {
            guard let vault = self.vault(vaultId) else {
                return completion(.failure(PigeonError(
                    code: "misconfigured",
                    message: "no such vault: it was disposed, or never created",
                    details: nil
                )))
            }
            do {
                completion(.success(try body(vault)))
            } catch {
                completion(.failure(Self.flutterError(error)))
            }
        }
    }

    private func resolveDirectory(_ requested: String?) throws -> URL {
        if let requested { return URL(fileURLWithPath: requested) }
        // Application Support, not Caches: the OS evicts Caches under storage pressure, which
        // would destroy the envelope and strand the user on the recovery path.
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        )
        let dir = base.appendingPathComponent("envelock", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func decodeFactor(_ f: WireRecoveryFactor) throws -> FfiRecoveryFactor {
        if let bytes = f.highEntropyBytes { return .highEntropy(bytes: bytes.data) }
        if let value = f.passphrase { return .passphrase(value: value) }
        throw FfiVaultError.Misconfigured(detail: "the recovery factor was empty")
    }

    private static func wireBacking(_ b: FfiHardwareBacking) -> WireHardwareBacking {
        switch b {
        case .secureEnclave: return .secureEnclave
        case .strongBox: return .strongBox
        case .tee: return .tee
        case .software: return .software
        }
    }

    fileprivate static func codeName(_ c: WireErrorCode) -> String {
        switch c {
        case .cancelled: return "cancelled"
        case .unavailable: return "unavailable"
        case .denied: return "denied"
        case .misconfigured: return "misconfigured"
        case .providerMaterialMismatch: return "providerMaterialMismatch"
        case .providerKeyRotated: return "providerKeyRotated"
        case .materialRejected: return "materialRejected"
        case .corruptData: return "corruptData"
        case .unexpected: return "unexpected"
        }
    }

    /// Surface the taxonomy code, so Dart can branch on it rather than parse a message.
    private static func flutterError(_ error: Error) -> PigeonError {
        guard let e = error as? FfiVaultError else {
            return PigeonError(code: "unavailable", message: "\(error)", details: nil)
        }
        let (code, message): (String, String) = {
            switch e {
            case .Cancelled: return ("cancelled", "cancelled by user")
            case .Unavailable: return ("unavailable", "key material temporarily unavailable")
            case .Denied: return ("denied", "access denied")
            case .Misconfigured(let m): return ("misconfigured", m)
            case .ProviderMaterialMismatch(let m): return ("providerMaterialMismatch", m)
            case .ProviderKeyRotated(let m): return ("providerKeyRotated", m)
            case .MaterialRejected(let m): return ("materialRejected", m)
            case .CorruptData(let m): return ("corruptData", m)
            case .Unexpected(let m): return ("unexpected", m)
            }
        }()
        return PigeonError(code: code, message: message, details: nil)
    }
}

// MARK: - Bridged providers

private final class BridgedMaterialProvider: KeyMaterialProviderFfi {
    private weak var plugin: EnvelockPlugin?
    private let vaultId: String
    init(plugin: EnvelockPlugin, vaultId: String) {
        self.plugin = plugin
        self.vaultId = vaultId
    }

    func getKeyMaterial(ctx: FfiMaterialContext) throws -> FfiKeyMaterial {
        guard let plugin else {
            print("[envelock] the plugin was deallocated while a provider callback was in flight")
            throw FfiVaultError.Unavailable
        }

        let reason: WireMaterialReason
        switch ctx.reason {
        case .enroll: reason = .enroll
        case .unlock: reason = .unlock
        case .rotate: reason = .rotate
        }

        let answer = try plugin.askDart(vaultId: vaultId, deadlineMs: ctx.deadlineMs) { api, requestId in
            api.onKeyMaterialRequested(
                ctx: WireMaterialContext(
                    vaultId: self.vaultId,
                    requestId: requestId,
                    reason: reason,
                    nonce: FlutterStandardTypedData(bytes: ctx.nonce),
                    deadlineMs: Int64(ctx.deadlineMs)
                )
            ) { _ in }
        }

        // Dart packs `keyId`, `cacheable` and `cacheTtlMs` NUL-separated into the text field,
        // so the record can be rebuilt without a second round trip. NUL and not a space: a
        // keyId is an arbitrary provider string and may well contain one.
        guard
            let material = answer.bytes,
            let text = answer.text
        else {
            throw FfiVaultError.Misconfigured(detail: "getKeyMaterial returned nothing")
        }

        let parts = text.split(separator: "\0", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            throw FfiVaultError.Misconfigured(
                // The text carries only keyId and cache policy, never the material, so
                // quoting it here is safe and saves a debugging round trip.
                detail: "getKeyMaterial returned a malformed result: "
                    + "\(parts.count) NUL-separated fields, expected 3"
            )
        }

        return FfiKeyMaterial(
            material: material,
            keyId: parts[0],
            cacheable: parts[1] == "true",
            cacheTtlMs: UInt64(parts[2]) ?? 30 * 24 * 60 * 60 * 1000
        )
    }
}

private final class BridgedRecoveryProvider: RecoveryProviderFfi {
    private weak var plugin: EnvelockPlugin?
    private let vaultId: String
    init(plugin: EnvelockPlugin, vaultId: String) {
        self.plugin = plugin
        self.vaultId = vaultId
    }

    func getRecoveryFactor(reason: FfiRecoveryReason) throws -> FfiRecoveryFactor {
        guard let plugin else {
            print("[envelock] the plugin was deallocated while a provider callback was in flight")
            throw FfiVaultError.Unavailable
        }

        let wire: WireRecoveryReason
        switch reason {
        case .migrate: wire = .migrate
        case .fallback: wire = .fallback
        case .change: wire = .change
        }

        // A human is typing or approving; give them real time.
        let answer = try plugin.askDart(vaultId: vaultId, deadlineMs: 300_000) { api, requestId in
            api.onRecoveryFactorRequested(
                vaultId: self.vaultId, requestId: requestId, reason: wire
            ) { _ in }
        }

        if let bytes = answer.bytes, answer.text == "highEntropy" {
            return .highEntropy(bytes: bytes)
        }
        if let text = answer.text, text.hasPrefix("passphrase\0") {
            return .passphrase(value: String(text.dropFirst("passphrase\0".count)))
        }
        throw FfiVaultError.Misconfigured(detail: "unrecognised recovery factor encoding")
    }
}

private final class BridgedEventSink: SecurityEventSinkFfi {
    private weak var plugin: EnvelockPlugin?
    private let vaultId: String
    init(plugin: EnvelockPlugin, vaultId: String) {
        self.plugin = plugin
        self.vaultId = vaultId
    }

    func onEvent(event: FfiSecurityEvent) {
        guard let plugin, let api = plugin.flutterApi else { return }

        var wire = WireSecurityEvent(type: "unknown")
        switch event {
        case .enrolled(let hardware):
            wire = WireSecurityEvent(type: "enrolled", hardware: Self.backing(hardware))
        case .unlocked(let usedCache):
            wire = WireSecurityEvent(type: "unlocked", usedCache: usedCache)
        case .recoveryUsed:
            wire = WireSecurityEvent(type: "recoveryUsed")
        case .unlockFailed(let counted):
            wire = WireSecurityEvent(type: "unlockFailed", counted: counted)
        case .providerKeyRotated(let from, let to):
            wire = WireSecurityEvent(type: "providerKeyRotated", from: from, to: to)
        case .materialFetched(let reason):
            wire = WireSecurityEvent(type: "materialFetched", reason: "\(reason)")
        case .materialCacheEvicted(let reason):
            wire = WireSecurityEvent(type: "materialCacheEvicted", reason: reason)
        case .lockedOut(let untilMs):
            wire = WireSecurityEvent(type: "lockedOut", untilMs: Int64(untilMs))
        case .vaultDestroyed(let reason):
            wire = WireSecurityEvent(type: "vaultDestroyed", reason: reason)
        case .hardwareDowngraded(let to):
            wire = WireSecurityEvent(type: "hardwareDowngraded", hardware: Self.backing(to))
        }

        // Platform channels are main-thread only, and this may fire from a Rust thread.
        let event = wire
        let id = vaultId
        DispatchQueue.main.async { api.onSecurityEvent(vaultId: id, event: event) { _ in } }
    }

    private static func backing(_ b: FfiHardwareBacking) -> WireHardwareBacking {
        switch b {
        case .secureEnclave: return .secureEnclave
        case .strongBox: return .strongBox
        case .tee: return .tee
        case .software: return .software
        }
    }
}

// MARK: - Pending callback registry

/// Tracks in-flight requests to Dart.
///
/// Every registered waiter must be resolved exactly once, including when the plugin is
/// disposed mid-flight - a leaked waiter is a thread blocked until its timeout, holding
/// whatever the Rust core was doing.
private final class PendingCallbacks {
    final class Waiter {
        private let semaphore = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var bytes: Data?
        private var text: String?
        private var failure: (code: String, message: String)?

        func complete(bytes: Data?, text: String?, error: (String, String)?) {
            lock.lock()
            self.bytes = bytes
            self.text = text
            self.failure = error.map { (code: $0.0, message: $0.1) }
            lock.unlock()
            semaphore.signal()
        }

        func wait(timeoutMs: UInt64) throws -> (bytes: Data?, text: String?) {
            guard semaphore.wait(timeout: .now() + .milliseconds(Int(timeoutMs))) == .success else {
                throw FfiVaultError.Unavailable
            }
            lock.lock()
            defer { lock.unlock() }
            if let failure { throw Self.error(failure.code, failure.message) }
            return (bytes, text)
        }

        /// Unrecognised codes become `Unavailable`: retryable and uncounted (spec 7.4).
        private static func error(_ code: String, _ message: String) -> FfiVaultError {
            switch code {
            case "cancelled": return .Cancelled
            case "denied": return .Denied
            case "misconfigured": return .Misconfigured(detail: message)
            default: return .Unavailable
            }
        }
    }

    private let lock = NSLock()
    private var waiters: [String: (vaultId: String, waiter: Waiter)] = [:]

    func register(_ id: String, vaultId: String) -> Waiter {
        let waiter = Waiter()
        lock.lock()
        waiters[id] = (vaultId: vaultId, waiter: waiter)
        lock.unlock()
        return waiter
    }

    func resolve(_ id: String, bytes: Data?, text: String?, error: (String, String)?) {
        lock.lock()
        let entry = waiters.removeValue(forKey: id)
        lock.unlock()

        guard let entry else {
            print(
                "[envelock] provider callback \(id) answered after envelock had given up; "
                    + "the result was discarded and reported as `unavailable`"
            )
            return
        }
        entry.waiter.complete(bytes: bytes, text: text, error: error)
    }

    func failAll(vaultId: String, code: String, message: String) {
        lock.lock()
        let doomed = waiters.filter { $0.value.vaultId == vaultId }
        for id in doomed.keys { waiters.removeValue(forKey: id) }
        lock.unlock()
        for entry in doomed.values {
            entry.waiter.complete(bytes: nil, text: nil, error: (code, message))
        }
    }

    func failAllRemaining(code: String, message: String) {
        lock.lock()
        let all = waiters
        waiters.removeAll()
        lock.unlock()
        for entry in all.values {
            entry.waiter.complete(bytes: nil, text: nil, error: (code, message))
        }
    }
}
