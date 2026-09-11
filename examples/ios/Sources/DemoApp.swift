import EnvelockCore
import SwiftUI

/// envelock on native iOS.
///
/// Walks the whole lifecycle so each step can be seen in isolation: enroll, lock, unlock,
/// write, read, recover, destroy. The log pane shows what actually happened, including which
/// errors are benign.
///
/// ## What to watch for
///
/// - **Unlock prompts once**, then reads records with no further prompt and no network.
/// - **Cancelling the Face ID prompt** produces `Cancelled`, not a lockout. Dismissing a
///   prompt is normal behaviour, not a failed authentication.
/// - **"Simulate new device"** deletes the enclave key. The state becomes `needsRecovery`, and
///   recovery rewraps so the *next* unlock is biometric-only again.
///
/// ## Run this on a physical device
///
/// The Simulator has no Secure Enclave. It still runs, and `securityInfo()` reports `software`
/// truthfully, but nothing is hardware-backed there, so the security floor does not hold.
///
/// ## Two demos, one app
///
/// **Vault directly** is `DemoScreen`: envelock as a standalone library, driven by the app
/// itself. **Inside an SDK** is `SdkDemoScreen`, where the same vault is baked into a product
/// SDK (`ShareRingVaultSdk`) that exposes four calls and hides the vault entirely. envelock
/// depends on neither arrangement; both are just ways to consume it.
@main
struct DemoApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                DemoScreen()
                    .tabItem { Label("Vault directly", systemImage: "lock.shield") }
                SdkDemoScreen()
                    .tabItem { Label("Inside an SDK", systemImage: "shippingbox") }
            }
        }
    }
}

@MainActor
final class DemoModel: ObservableObject {

    @Published var state = "..."
    @Published var log: [String] = []
    @Published var fatal: String?

    private var vault: FfiVault?
    private var keyStore: SecureEnclaveKeyStore?
    private let recovery = DemoRecoveryProvider()

    private static let keychainService = "network.sharering.envelock.demo"

    func open() {
        do {
            let directory = FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("envelock", isDirectory: true)

            let (vault, keyStore) = try Envelock.makeVault(
                providerId: "envelock-demo",
                directory: directory,
                keychainService: Self.keychainService,
                // Swap for BackendMaterialProvider to see the real pattern; DemoProviders.swift
                // explains why a locally-stored pepper is not a second factor.
                material: LocalDemoMaterialProvider(),
                recovery: recovery,
                events: DemoEventSink { [weak self] line in
                    Task { @MainActor in self?.append(line) }
                }
            )
            self.vault = vault
            self.keyStore = keyStore
            refresh()
        } catch {
            fatal = "\(error)"
        }
    }

    /// Zeroize on background (spec 11.3).
    ///
    /// This happens inside the Rust core. Dropping a Swift reference gives no guarantee the key
    /// bytes ever leave memory, so the call has to be explicit.
    func background() {
        vault?.lock()
        keyStore?.invalidateContext()
        refresh()
    }

    func enroll() {
        act("enroll") { vault in
            try vault.enroll(factor: .highEntropy(bytes: DemoRecoveryProvider.demoKey))
            return "vault created, one prompt for enclave consent"
        }
    }

    func unlock() {
        act("unlock") { vault in
            try vault.unlock()
            return "one biometric prompt, cached material, no network"
        }
    }

    func lock() {
        act("lock") { vault in
            vault.lock()
            self.keyStore?.invalidateContext()
            return "DEK zeroized in Rust"
        }
    }

    func write() {
        act("put") { vault in
            try vault.put(recordId: "card:1", plaintext: Data("4111 1111 1111 1111".utf8))
            return "wrote card:1"
        }
    }

    func read() {
        act("get") { vault in
            guard let bytes = try vault.get(recordId: "card:1") else { return "no such record" }
            return String(decoding: bytes)
        }
    }

    func list() {
        act("list") { vault in try "\(vault.list(prefix: ""))" }
    }

    func info() {
        act("security info") { vault in
            let i = try vault.securityInfo()
            return "\(i.hardwareBacking) (hardware=\(i.hardwareBacking.isHardwareBacked)) "
                + "keyId=\(i.keyId)"
        }
    }

    /// Delete the enclave key, which is exactly what restoring a backup onto new hardware looks
    /// like from envelock's side: the envelope survives, the device-bound key does not.
    func simulateNewDevice() {
        act("simulate new device") { vault in
            vault.lock()
            let removed = Self.deleteDemoKeychainEntries()
            return "deleted \(removed) keychain item(s); expect needsRecovery"
        }
    }

    func recover() {
        act("recover") { vault in
            try vault.unlockWithRecovery()
            return "recovered (\(self.recovery.lastReason.map { "\($0)" } ?? "?")); "
                + "primary path rewrapped, so the next unlock is biometric-only"
        }
    }

    func destroy() {
        act("destroy") { vault in
            try vault.destroyVault()
            return "enclave key, envelope, cache and records deleted - irreversible"
        }
    }

    // MARK: - Internals

    /// Run a vault call off the main thread (unlock blocks on a biometric prompt) and report
    /// the outcome.
    private func act(_ label: String, _ body: @escaping (FfiVault) throws -> String) {
        guard let vault else { return }

        Task.detached { [weak self] in
            let line: String
            do {
                line = "[ok] \(label) - \(try body(vault))"
            } catch let error as FfiVaultError {
                switch error {
                case .Cancelled:
                    // Normal behaviour, and explicitly not a failed attempt (spec 7.4).
                    line = "- \(label) - cancelled by user (not counted)"
                default:
                    line = "[x] \(label) - \(error)"
                }
            } catch {
                line = "[x] \(label) - \(error)"
            }

            await MainActor.run {
                self?.append(line)
                self?.refresh()
            }
        }
    }

    private func append(_ line: String) {
        log.insert(line, at: 0)
        if log.count > 40 { log.removeLast() }
    }

    private func refresh() {
        guard let vault else { return }
        switch vault.state() {
        case .notEnrolled: state = "notEnrolled"
        case .locked: state = "locked"
        case .unlocked: state = "unlocked"
        case .needsRecovery: state = "needsRecovery"
        case .lockedOut(let untilMs): state = "lockedOut until \(untilMs)"
        }
    }

    /// Delete this app's enclave keys and sealed secrets, to demonstrate recovery.
    ///
    /// Lives in the example rather than in envelock: production code has no business bulk-
    /// deleting keys, and adding an API for it would be an API that exists only to destroy
    /// user data.
    private static func deleteDemoKeychainEntries() -> Int {
        var deleted = 0
        for itemClass in [kSecClassKey, kSecClassGenericPassword] {
            let query: [String: Any] = [
                kSecClass as String: itemClass,
                kSecAttrService as String: keychainService,
            ]
            if SecItemDelete(query as CFDictionary) == errSecSuccess { deleted += 1 }
        }

        // Enclave keys are stored by application tag rather than service, so they need their
        // own sweep.
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        if SecItemDelete(keyQuery as CFDictionary) == errSecSuccess { deleted += 1 }
        return deleted
    }
}

private extension String {
    init(decoding data: Data) {
        self = String(data: data, encoding: .utf8) ?? data.base64EncodedString()
    }
}

struct DemoScreen: View {
    @StateObject private var model = DemoModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationView {
            Group {
                if let fatal = model.fatal {
                    ScrollView {
                        Text("Could not open the vault:\n\n\(fatal)")
                            .padding()
                    }
                } else {
                    content
                }
            }
            .navigationTitle("envelock")
        }
        .onAppear { model.open() }
        .onChange(of: scenePhase) { phase in
            // `.background`, not `!= .active`: the Face ID sheet and the app switcher both make
            // the scene `.inactive` while the app is still in use, and the Face ID sheet is
            // raised by `unlock()` itself.
            if phase == .background { model.background() }
        }
    }

    private var content: some View {
        List {
            Section("State") {
                Text(model.state).font(.system(.body, design: .monospaced))
                Button("Security info") { model.info() }
            }

            Section("Lifecycle") {
                Button("Enroll") { model.enroll() }
                Button("Unlock") { model.unlock() }
                Button("Lock") { model.lock() }
            }

            Section("Records") {
                Button("Write card:1") { model.write() }
                Button("Read card:1") { model.read() }
                Button("List") { model.list() }
            }

            Section("Recovery") {
                Button("Simulate new device") { model.simulateNewDevice() }
                Button("Recover") { model.recover() }
            }

            Section("Danger") {
                Button("Destroy vault", role: .destructive) { model.destroy() }
            }

            Section("Log") {
                if model.log.isEmpty {
                    Text("Tap Enroll to begin.").foregroundStyle(.secondary)
                }
                ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(.caption, design: .monospaced))
                }
            }
        }
    }
}
