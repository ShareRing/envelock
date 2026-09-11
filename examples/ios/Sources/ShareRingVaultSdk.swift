import EnvelockCore
import Foundation

/// A stand-in for a host SDK that has envelock baked in - the layer an external app installs.
///
/// envelock is *inside* this file, not in the app above it. The app never sees `FfiVault`,
/// never calls `put`/`get`/`list`, and never learns that a state machine exists. It gets four
/// entry points: ``initialize``, ``destroy``, ``getDocument``, ``getRecoveryFactor``: plus
/// ``background()``, because iOS gives the library no lifecycle hook it can install itself.
///
/// envelock does not depend on any of this, and nothing here is part of the library: it is a
/// worked example of wrapping a standalone vault inside a product SDK. `DemoApp.swift` drives
/// the same vault directly, which is the other half of the picture.

/// What the app hands the SDK. Everything envelock-shaped is here, and nothing else.
struct SdkVaultOptions {
    /// Namespaced into every derivation. **Changing it invalidates every existing vault.**
    let providerId: String
    /// Must return byte-identical material every call.
    let material: KeyMaterialProviderFfi
    /// Asked for the 12 words on a device that has never held them: a restored backup, a new
    /// phone. Called on a background thread from the Rust core and **must block** until the
    /// user answers; return an empty string if they dismiss the prompt.
    let promptRecoveryPhrase: (FfiRecoveryReason) -> String
    var events: SecurityEventSinkFfi?
}

struct SdkOptions {
    let appId: String
    let vaultOptions: SdkVaultOptions
    /// Where a document comes from the first time. After that it is served from the vault,
    /// offline, with no network call - that is the point of the vault.
    let fetchDocument: (String) throws -> Data
}

/// What the SDK does next, given what the vault says it is.
enum SdkStep { case ready, enroll, unlock, recover, lockedOut }

/// Pulled out as a free function so the routing can be reasoned about on its own; the vault's
/// own states never reach the app above.
func stepFor(_ state: FfiVaultState) -> SdkStep {
    switch state {
    case .unlocked: return .ready
    case .notEnrolled: return .enroll
    case .locked: return .unlock
    case .needsRecovery: return .recover
    case .lockedOut: return .lockedOut
    }
}

final class ShareRingVaultSdk {

    private let options: SdkOptions
    private let wordlist: [String]
    private var vault: FfiVault!
    private var keyStore: SecureEnclaveKeyStore!

    /// Held in memory only. Persisted inside the vault, never beside it: app storage is
    /// plaintext on a jailbroken device and the phrase opens everything.
    private let lock = NSLock()
    private var storedPhrase: String?

    private static let phraseRecord = "sys:recovery-phrase"

    private init(options: SdkOptions, wordlist: [String]) {
        self.options = options
        self.wordlist = wordlist
    }

    /// Opens the vault and enrolls if this is the first run.
    ///
    /// Blocking: enrollment prompts for enclave consent. Call it off the main thread.
    static func initialize(_ options: SdkOptions) throws -> ShareRingVaultSdk {
        let sdk = ShareRingVaultSdk(options: options, wordlist: try loadWordlist())
        let v = options.vaultOptions

        // Its own directory, so the SDK's vault and a vault the app opens itself never fight
        // over one envelope.
        let directory = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("sharering-sdk", isDirectory: true)

        let (vault, keyStore) = try Envelock.makeVault(
            providerId: v.providerId,
            directory: directory,
            keychainService: "network.sharering.envelock.demo.sdk",
            material: v.material,
            // The app supplies material; the SDK owns recovery. This is why there is no
            // recovery provider in `SdkVaultOptions`.
            recovery: SdkRecoveryProvider(sdk: sdk),
            events: v.events
        )
        sdk.vault = vault
        sdk.keyStore = keyStore

        try sdk.ready()
        return sdk
    }

    /// The 12 words. Show them once at setup and let the user write them down.
    ///
    /// Reading them needs an unlocked vault (they are stored in it) so this costs a biometric
    /// prompt on a locked session, which is the correct price for revealing them.
    func getRecoveryFactor() throws -> String {
        if let held = phrase { return held }

        try ready()
        guard let stored = try vault.get(recordId: Self.phraseRecord) else {
            throw FfiVaultError.CorruptData(
                detail: "the vault is enrolled but holds no recovery phrase"
            )
        }
        let text = String(data: stored, encoding: .utf8) ?? ""
        phrase = text
        return text
    }

    /// Cached in the vault after the first fetch; every later call is offline.
    func getDocument(_ documentId: String) throws -> [String: Any] {
        try ready()

        let id = "doc:\(documentId)"
        if let cached = try vault.get(recordId: id) { return try Self.decode(cached) }

        let fetched = try options.fetchDocument(documentId)
        try vault.put(recordId: id, plaintext: fetched)
        return try Self.decode(fetched)
    }

    /// Zeroize the in-memory key and drop the biometric context. Wire this to a scene phase
    /// leaving `.active`: zeroization has to happen inside the Rust core, because dropping a
    /// Swift reference guarantees nothing (spec 11.3).
    func background() {
        vault.lock()
        keyStore.invalidateContext()
    }

    /// Irreversible: enclave key, envelope, cache and every document. The 12 words do not bring
    /// this back - nothing does.
    func destroy() throws {
        try vault.destroyVault()
        phrase = nil
    }

    // MARK: - Internals

    private var phrase: String? {
        get { lock.withLock { storedPhrase } }
        set { lock.withLock { storedPhrase = newValue } }
    }

    /// Drive the vault to `unlocked`, whatever it currently is.
    private func ready() throws {
        let state = vault.state()

        switch stepFor(state) {
        case .ready:
            return

        case .enroll:
            // A passphrase factor, so the spec 10 backoff ladder applies and 11 failed attempts
            // destroy the vault. A wallet should derive 32 bytes from its seed with
            // envelock-bip85 and enroll a high-entropy factor instead, which has no ladder.
            let generated = generateRecoveryPhrase()
            try vault.enroll(factor: .passphrase(generated))
            phrase = generated

            // Enrollment is atomic: a vault enrolled with a phrase that never reached storage is
            // unopenable by anyone, so tear it down rather than leave that behind.
            do {
                try vault.put(recordId: Self.phraseRecord, plaintext: Data(generated.utf8))
            } catch {
                try? vault.destroyVault()
                phrase = nil
                throw error
            }

        case .unlock:
            try vault.unlock()

        case .recover:
            // Rewraps the primary path in the same operation, so the next unlock is
            // biometric-only.
            try vault.unlockWithRecovery()

        case .lockedOut:
            // Retrying here would burn an attempt against a ladder that is already throttling.
            guard case .lockedOut(let untilMs) = state else { return }
            throw FfiVaultError.Misconfigured(
                detail: "too many failed recovery attempts; retry after \(untilMs)"
            )
        }
    }

    /// 12 words drawn from the BIP-39 English list with the system CSPRNG: 132 bits.
    private func generateRecoveryPhrase() -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        // `SystemRandomNumberGenerator` is already the CSPRNG, but going through SecRandom keeps
        // the source explicit for anyone auditing this file.
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        return (0..<12).map { i in
            let index = (Int(bytes[i * 2]) << 8 | Int(bytes[i * 2 + 1])) & 0x7ff
            return wordlist[index]
        }.joined(separator: " ")
    }

    /// The BIP-39 English wordlist, shared with the Android and React Native examples through
    /// `examples/shared` so there is exactly one copy of it.
    private static func loadWordlist() throws -> [String] {
        guard let url = Bundle.main.url(forResource: "bip39-english", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let words = try? JSONDecoder().decode([String].self, from: data)
        else {
            throw FfiVaultError.Misconfigured(detail: "bip39-english.json is missing from the bundle")
        }
        return words
    }

    private static func decode(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw FfiVaultError.CorruptData(detail: "the stored document is not a JSON object")
        }
        return object
    }

    /// Serves the recovery factor from the phrase the SDK holds, or asks the app for it.
    private final class SdkRecoveryProvider: RecoveryProviderFfi {
        // A weak back-reference: the SDK owns the vault, the vault owns this. Never reassigned
        // after init, which is what the unchecked annotation asserts.
        nonisolated(unsafe) private weak var sdk: ShareRingVaultSdk?
        init(sdk: ShareRingVaultSdk) { self.sdk = sdk }

        func getRecoveryFactor(reason: FfiRecoveryReason) throws -> FfiRecoveryFactor {
            guard let sdk else { throw FfiVaultError.Unavailable }

            let typed = (sdk.phrase ?? sdk.options.vaultOptions.promptRecoveryPhrase(reason))
                .split(whereSeparator: \.isWhitespace)
                .map(String.init)

            // A mistyped word never reaches the KDF. Not `Denied`: nothing was verified, so
            // this must not spend one of the 11 attempts (spec 7.4).
            guard typed.count == 12, typed.allSatisfy(sdk.wordlist.contains) else {
                throw FfiVaultError.Cancelled
            }

            let phrase = typed.joined(separator: " ")
            sdk.phrase = phrase
            return .passphrase(phrase)
        }
    }
}
