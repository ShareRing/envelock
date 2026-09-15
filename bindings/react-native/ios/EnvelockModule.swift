import EnvelockCore
import Foundation
import React

/// The React Native module.
///
/// ## How a synchronous Rust callback reaches an asynchronous JS function
///
/// The Rust core calls `getKeyMaterial` and waits; a JS provider returns a `Promise`.
///
/// 1. Every vault method runs on a background queue, so the JS thread is never blocked.
/// 2. When Rust needs material, the native provider emits an event with a request id and blocks
///    *its own* background thread on a semaphore.
/// 3. JS runs the callback and calls `resolveCallback(requestId, ...)`.
/// 4. The semaphore is signalled and the Rust call returns.
///
/// This cannot deadlock, because step 1 left the JS thread free. If JS never answers, the
/// semaphore times out as `unavailable` and envelock's own deadline sits underneath, so a wedged
/// JS thread degrades to a retryable error rather than a hang.
@objc(RNEnvelock)
final class EnvelockModule: RCTEventEmitter {

    private static let keyMaterialEvent = "envelock:getKeyMaterial"
    private static let recoveryEvent = "envelock:getRecoveryFactor"
    private static let securityEvent = "envelock:securityEvent"

    private let queue = DispatchQueue(label: "network.sharering.envelock.rn", attributes: .concurrent)
    private let pending = PendingCallbacks()

    private let registry = NSLock()
    private var vaults: [String: FfiVault] = [:]
    private var keyStores: [String: SecureEnclaveKeyStore] = [:]
    private var listening = false

    override static func requiresMainQueueSetup() -> Bool { false }

    override func supportedEvents() -> [String] {
        [Self.keyMaterialEvent, Self.recoveryEvent, Self.securityEvent]
    }

    override func startObserving() { listening = true }
    override func stopObserving() { listening = false }

    // MARK: - Lifecycle

    @objc(create:resolve:reject:)
    func create(
        _ config: NSDictionary,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        queue.async {
            do {
                let providerId = config["providerId"] as? String ?? ""
                let directory = try self.resolveDirectory(config["directory"] as? String)

                var vaultConfig = defaultConfig(providerId: providerId, dir: directory.path)
                if let v = config["autoLockMs"] as? NSNumber { vaultConfig.autoLockMs = v.uint64Value }
                if let v = config["callbackDeadlineMs"] as? NSNumber {
                    vaultConfig.callbackDeadlineMs = v.uint64Value
                }
                // `null` from JS disables destruction entirely; anything else is the limit.
                vaultConfig.destroyAfterAttempts =
                    (config["destroyAfterAttempts"] as? NSNumber)?.uint32Value

                let store = SecureEnclaveKeyStore(service: "network.sharering.envelock.\(providerId)")
                let vaultId = UUID().uuidString
                let vault = try FfiVault(
                    config: vaultConfig,
                    enclave: store,
                    material: BridgedMaterialProvider(module: self, vaultId: vaultId),
                    recovery: BridgedRecoveryProvider(module: self, vaultId: vaultId),
                    events: BridgedEventSink(module: self, vaultId: vaultId)
                )

                self.registry.lock()
                self.vaults[vaultId] = vault
                self.keyStores[vaultId] = store
                self.registry.unlock()

                resolve("\(vaultId) \(directory.path)")
            } catch {
                Self.rejectWith(error, reject)
            }
        }
    }

    @objc(destroyInstance:resolve:reject:)
    func destroyInstance(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        queue.async {
            self.registry.lock()
            let vault = self.vaults.removeValue(forKey: vaultId)
            let store = self.keyStores.removeValue(forKey: vaultId)
            self.registry.unlock()

            vault?.lock()
            store?.invalidateContext()
            self.pending.failAll(
                vaultId: vaultId,
                code: "unavailable",
                message: "the vault was disposed"
            )
            resolve(nil)
        }
    }

    // MARK: - Vault operations

    @objc(state:resolve:reject:)
    func state(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { vault in
            switch vault.state() {
            case .notEnrolled: return "not_enrolled"
            case .locked: return "locked"
            case .unlocked: return "unlocked"
            case .needsRecovery: return "needs_recovery"
            case .lockedOut(let untilMs): return "locked_out:\(untilMs)"
            }
        }
    }

    /// A high-entropy factor arrives as a buffer token; a passphrase is inherently a string,
    /// so there is nothing to gain by tokenizing it.
    @objc(enroll:kind:token:passphrase:resolve:reject:)
    func enroll(
        _ vaultId: String,
        kind: String,
        token: NSNumber,
        passphrase: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) {
            try $0.enroll(factor: Self.decodeFactor(kind, token.uint64Value, passphrase))
            return nil
        }
    }

    @objc(unlock:resolve:reject:)
    func unlock(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { try $0.unlock(); return nil }
    }

    @objc(unlockWithRecovery:resolve:reject:)
    func unlockWithRecovery(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { try $0.unlockWithRecovery(); return nil }
    }

    @objc(changeRecoveryFactor:kind:token:passphrase:resolve:reject:)
    func changeRecoveryFactor(
        _ vaultId: String,
        kind: String,
        token: NSNumber,
        passphrase: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) {
            try $0.changeRecoveryFactor(
                newFactor: Self.decodeFactor(kind, token.uint64Value, passphrase)
            )
            return nil
        }
    }

    /// `token` names bytes JavaScript already handed to the JSI buffer registry, so no
    /// record content is ever a JavaScript string.
    @objc(put:recordId:token:resolve:reject:)
    func put(
        _ vaultId: String,
        recordId: String,
        token: NSNumber,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) {
            guard let data = BufferBridge.take(token.uint64Value) else {
                throw FfiVaultError.Misconfigured(
                    detail: "unknown or already-redeemed buffer token"
                )
            }
            defer { BufferBridge.zeroize(data) }
            try $0.put(recordId: recordId, plaintext: data)
            return nil
        }
    }

    /// Returns a token JavaScript redeems for an `ArrayBuffer`, or `0` for a missing record.
    @objc(get:recordId:resolve:reject:)
    func get(
        _ vaultId: String,
        recordId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { vault in
            guard let data = try vault.get(recordId: recordId) else { return NSNumber(value: 0) }
            return NSNumber(value: BufferBridge.put(data))
        }
    }

    @objc(remove:recordId:resolve:reject:)
    func remove(
        _ vaultId: String,
        recordId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { try $0.delete(recordId: recordId); return nil }
    }

    @objc(list:prefix:resolve:reject:)
    func list(
        _ vaultId: String,
        prefix: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { try $0.list(prefix: prefix) }
    }

    @objc(lock:resolve:reject:)
    func lock(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { vault in
            vault.lock()
            // Drop the cached authentication too, so returning to the foreground re-prompts.
            self.keyStore(vaultId)?.invalidateContext()
            return nil
        }
    }

    @objc(destroyVault:resolve:reject:)
    func destroyVault(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { try $0.destroyVault(); return nil }
    }

    @objc(securityInfo:resolve:reject:)
    func securityInfo(
        _ vaultId: String,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        run(vaultId, resolve, reject) { vault in
            let i = try vault.securityInfo()
            let json: [String: Any] = [
                "hardwareBacking": Self.name(i.hardwareBacking),
                "providerId": i.providerId,
                "keyId": i.keyId,
                "recoveryKind": i.recoveryKind == .highEntropy ? "highEntropy" : "passphrase",
                "enrolledAt": i.enrolledAt,
                "failedAttempts": i.failedAttempts,
                "lockedUntil": i.lockedUntil,
                "materialCachedUntil": i.materialCachedUntil as Any,
            ]
            return String(data: try JSONSerialization.data(withJSONObject: json), encoding: .utf8)
        }
    }

    // MARK: - Callback plumbing

    @objc(resolveCallback:token:text:errorCode:errorMessage:)
    func resolveCallback(
        _ requestId: String,
        token: NSNumber,
        text: String,
        errorCode: String,
        errorMessage: String
    ) {
        pending.resolve(
            requestId,
            token: token.uint64Value,
            text: text,
            error: errorCode.isEmpty ? nil : (errorCode, errorMessage)
        )
    }

    /// Ask JS for something and block this (background) thread until it answers.
    fileprivate func askJS(
        vaultId: String,
        event: String,
        body: [String: Any],
        deadlineMs: UInt64
    ) throws -> (bytes: Data?, text: String) {
        guard listening else {
            throw FfiVaultError.Misconfigured(
                detail: "no JS listener is attached; create the vault through the JS API"
            )
        }

        let requestId = UUID().uuidString
        let waiter = pending.register(requestId, vaultId: vaultId)

        var payload = body
        payload["requestId"] = requestId
        // JavaScript dispatches on this: one router for the process, not a listener per vault.
        payload["vaultId"] = vaultId
        sendEvent(withName: event, body: payload)

        // A generous margin over envelock's own deadline: the core is the authority on timing,
        // and this only exists so a JS thread that never answers cannot wedge a thread forever.
        return try waiter.wait(timeoutMs: deadlineMs + 5_000)
    }

    // MARK: - Helpers

    private func run(
        _ vaultId: String,
        _ resolve: @escaping RCTPromiseResolveBlock,
        _ reject: @escaping RCTPromiseRejectBlock,
        _ body: @escaping (FfiVault) throws -> Any?
    ) {
        queue.async {
            guard let vault = self.vault(vaultId) else {
                reject("misconfigured", "no such vault: it was disposed, or never created", nil)
                return
            }
            do {
                resolve(try body(vault))
            } catch {
                Self.rejectWith(error, reject)
            }
        }
    }

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

    private static func decodeFactor(
        _ kind: String,
        _ token: UInt64,
        _ passphrase: String
    ) throws -> FfiRecoveryFactor {
        switch kind {
        case "highEntropy":
            guard let bytes = BufferBridge.take(token) else {
                throw FfiVaultError.Misconfigured(
                    detail: "unknown or already-redeemed buffer token"
                )
            }
            defer { BufferBridge.zeroize(bytes) }
            return .highEntropy(bytes: bytes)
        case "passphrase":
            return .passphrase(value: passphrase)
        default:
            throw FfiVaultError.Misconfigured(detail: "unrecognised recovery factor kind")
        }
    }

    private static func name(_ b: FfiHardwareBacking) -> String {
        switch b {
        case .secureEnclave: return "secureEnclave"
        case .strongBox: return "strongBox"
        case .tee: return "tee"
        case .software: return "software"
        }
    }

    /// Reject with the taxonomy code, so JS can branch on it rather than parse a message.
    private static func rejectWith(_ error: Error, _ reject: RCTPromiseRejectBlock) {
        guard let e = error as? FfiVaultError else {
            return reject("unavailable", error.localizedDescription, error)
        }
        switch e {
        case .Cancelled: reject("cancelled", "cancelled by user", error)
        case .Unavailable: reject("unavailable", "key material temporarily unavailable", error)
        case .Denied: reject("denied", "access denied", error)
        case .Misconfigured(let m): reject("misconfigured", m, error)
        case .ProviderMaterialMismatch(let m): reject("providerMaterialMismatch", m, error)
        case .ProviderKeyRotated(let m): reject("providerKeyRotated", m, error)
        case .MaterialRejected(let m): reject("materialRejected", m, error)
        case .CorruptData(let m): reject("corruptData", m, error)
        case .Unexpected(let m): reject("unexpected", m, error)
        }
    }
}

// MARK: - Bridged providers

private final class BridgedMaterialProvider: KeyMaterialProviderFfi {
    private let vaultId: String
    private weak var module: EnvelockModule?
    init(module: EnvelockModule, vaultId: String) {
        self.module = module
        self.vaultId = vaultId
    }

    func getKeyMaterial(ctx: FfiMaterialContext) throws -> FfiKeyMaterial {
        guard let module else { throw FfiVaultError.Unavailable }

        let reason: String
        switch ctx.reason {
        case .enroll: reason = "enroll"
        case .unlock: reason = "unlock"
        case .rotate: reason = "rotate"
        }

        // The nonce goes out as a token too, so nothing about this exchange is a JS string.
        let answer = try module.askJS(
            vaultId: vaultId,
            event: "envelock:getKeyMaterial",
            body: [
                "reason": reason,
                "nonceToken": NSNumber(value: BufferBridge.put(ctx.nonce)),
                "deadlineMs": ctx.deadlineMs,
            ],
            deadlineMs: ctx.deadlineMs
        )

        // JS packs `keyId cacheable cacheTtlMs` into the text field; the material itself came
        // back as bytes.
        let parts = answer.text.split(separator: " ", maxSplits: 2).map(String.init)
        guard let material = answer.bytes, parts.count == 3 else {
            throw FfiVaultError.Misconfigured(
                detail: "getKeyMaterial returned a malformed result"
            )
        }
        defer { BufferBridge.zeroize(material) }

        return FfiKeyMaterial(
            material: material,
            keyId: parts[0],
            cacheable: parts[1] == "true",
            cacheTtlMs: UInt64(parts[2]) ?? 30 * 24 * 60 * 60 * 1000
        )
    }
}

private final class BridgedRecoveryProvider: RecoveryProviderFfi {
    private let vaultId: String
    private weak var module: EnvelockModule?
    init(module: EnvelockModule, vaultId: String) {
        self.module = module
        self.vaultId = vaultId
    }

    func getRecoveryFactor(reason: FfiRecoveryReason) throws -> FfiRecoveryFactor {
        guard let module else { throw FfiVaultError.Unavailable }

        let name: String
        switch reason {
        case .migrate: name = "migrate"
        case .fallback: name = "fallback"
        case .change: name = "change"
        }

        let answer = try module.askJS(
            vaultId: vaultId,
            event: "envelock:getRecoveryFactor",
            body: ["reason": name],
            deadlineMs: 300_000  // A human is typing or approving; give them real time.
        )

        if answer.text == "highEntropy", let bytes = answer.bytes {
            defer { BufferBridge.zeroize(bytes) }
            return .highEntropy(bytes: bytes)
        }
        if answer.text.hasPrefix("passphrase ") {
            return .passphrase(value: String(answer.text.dropFirst("passphrase ".count)))
        }
        throw FfiVaultError.Misconfigured(detail: "unrecognised recovery factor encoding")
    }
}

private final class BridgedEventSink: SecurityEventSinkFfi {
    private let vaultId: String
    private weak var module: EnvelockModule?
    init(module: EnvelockModule, vaultId: String) {
        self.module = module
        self.vaultId = vaultId
    }

    func onEvent(event: FfiSecurityEvent) {
        var body: [String: Any] = [:]
        switch event {
        case .enrolled(let hardware): body = ["type": "enrolled", "hardware": "\(hardware)"]
        case .unlocked(let usedCache): body = ["type": "unlocked", "usedCache": usedCache]
        case .recoveryUsed: body = ["type": "recoveryUsed"]
        case .unlockFailed(let counted): body = ["type": "unlockFailed", "counted": counted]
        case .providerKeyRotated(let from, let to):
            body = ["type": "providerKeyRotated", "from": from, "to": to]
        case .materialFetched(let reason): body = ["type": "materialFetched", "reason": "\(reason)"]
        case .materialCacheEvicted(let reason):
            body = ["type": "materialCacheEvicted", "reason": reason]
        case .lockedOut(let untilMs): body = ["type": "lockedOut", "untilMs": untilMs]
        case .vaultDestroyed(let reason): body = ["type": "vaultDestroyed", "reason": reason]
        case .hardwareDowngraded(let to): body = ["type": "hardwareDowngraded", "to": "\(to)"]
        }
        var payload = body
        payload["vaultId"] = vaultId
        module?.sendEvent(withName: "envelock:securityEvent", body: payload)
    }
}

// MARK: - Pending callback registry

/// Tracks in-flight requests to JS.
///
/// Every registered waiter must be resolved exactly once, including when the vault is disposed
/// mid-flight - a leaked waiter is a thread blocked until its timeout, holding whatever the
/// Rust core was doing.
private final class PendingCallbacks {
    final class Waiter {
        private let semaphore = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var bytes: Data?
        private var text: String = ""
        private var failure: (code: String, message: String)?

        func complete(token: UInt64, text: String, error: (String, String)?) {
            lock.lock()
            self.bytes = token == 0 ? nil : BufferBridge.take(token)
            self.text = text
            self.failure = error.map { (code: $0.0, message: $0.1) }
            lock.unlock()
            semaphore.signal()
        }

        func wait(timeoutMs: UInt64) throws -> (bytes: Data?, text: String) {
            let deadline = DispatchTime.now() + .milliseconds(Int(timeoutMs))
            guard semaphore.wait(timeout: deadline) == .success else {
                throw FfiVaultError.Unavailable
            }
            lock.lock()
            defer { lock.unlock() }
            if let failure { throw Self.error(failure.code, failure.message) }
            return (bytes, text)
        }

        /// Map the taxonomy code JS sent back onto a typed error.
        ///
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

    func resolve(_ id: String, token: UInt64, text: String, error: (String, String)?) {
        lock.lock()
        let entry = waiters.removeValue(forKey: id)
        lock.unlock()

        guard let waiter = entry?.waiter else {
            // Nobody is waiting - the request timed out or the vault was disposed. The payload
            // must still be released, or an abandoned secret sits in memory until exit.
            if token != 0 { BufferBridge.drop(token) }
            return
        }
        waiter.complete(token: token, text: text, error: error)
    }

    func failAll(vaultId: String, code: String, message: String) {
        lock.lock()
        let doomed = waiters.filter { $0.value.vaultId == vaultId }
        for id in doomed.keys { waiters.removeValue(forKey: id) }
        lock.unlock()
        for entry in doomed.values {
            entry.waiter.complete(token: 0, text: "", error: (code, message))
        }
    }
}

// MARK: - Buffer registry

/// The Swift face of the JSI buffer registry in `cpp/EnvelockJSI.cpp`.
///
/// Bytes move between JavaScript and Rust through native memory rather than base64 strings.
/// That removes an encode and a decode from the JS thread, and - the part that matters -
/// keeps provider material out of immutable JavaScript strings, which cannot be zeroized and
/// linger until the heap is collected.
enum BufferBridge {
    /// Redeem a token for its bytes. Single-use: an unknown or already-redeemed token is nil.
    static func take(_ token: UInt64) -> Data? {
        var pointer: UnsafeMutablePointer<UInt8>?
        var length = 0
        guard envelock_buffer_take(token, &pointer, &length), let pointer else { return nil }
        defer { envelock_buffer_free(pointer, length) }
        return Data(bytes: pointer, count: length)
    }

    /// Hand bytes to the registry and return the token JavaScript redeems.
    static func put(_ data: Data) -> UInt64 {
        data.withUnsafeBytes { raw in
            envelock_buffer_put(raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
    }

    /// Release a token nobody will redeem, zeroizing what it held.
    static func drop(_ token: UInt64) {
        envelock_buffer_drop(token)
    }

    /// Overwrite a `Data` before it goes out of scope.
    ///
    /// Swift `Data` has no zeroizing storage, so this is best-effort: a copy-on-write copy made
    /// earlier is not reached. It still removes the longest-lived copy, which is the one that
    /// matters.
    static func zeroize(_ data: Data) {
        var mutable = data
        mutable.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            memset_s(base, raw.count, 0, raw.count)
        }
    }
}
