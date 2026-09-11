import EnvelockCore
import Foundation

/// A material provider that keeps the pepper on the device.
///
/// ## Demo only - this is not a second factor
///
/// A locally-stored pepper sits next to the envelope, so a jailbroken device yields both and the
/// material adds nothing the enclave key was not already contributing. The vault still has the
/// hardware key behind its OS gate, but you no longer get two independent factors. Point
/// ``BackendMaterialProvider`` at something like `examples/reference-backend` for that.
///
/// What it does get right: the bytes are written once and read back forever. That is the
/// determinism contract, and the part integrators break.
final class LocalDemoMaterialProvider: KeyMaterialProviderFfi {

    private let url: URL
    private let lock = NSLock()

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        url = base.appendingPathComponent("demo-pepper.bin")
    }

    func getKeyMaterial(ctx: FfiMaterialContext) throws -> FfiKeyMaterial {
        lock.lock()
        defer { lock.unlock() }

        let material: Data
        if let existing = try? Data(contentsOf: url) {
            material = existing
        } else {
            var fresh = Data(count: 32)
            let status = fresh.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
            }
            guard status == errSecSuccess else { throw FfiVaultError.Unavailable }
            // `.completeFileProtection` so it is unreadable while the device is locked, and
            // never included in a backup that could land on another device.
            try? fresh.write(to: url, options: [.atomic, .completeFileProtection])
            material = fresh
        }

        return FfiKeyMaterial(
            material: material,
            // A fixed keyId: rotation is a deliberate act, never a side effect of a call.
            keyId: "demo-v1",
            cacheable: true,
            cacheTtlMs: 30 * 24 * 60 * 60 * 1000
        )
    }
}

/// The shape a real provider takes (spec 9.1).
///
/// Point it at `examples/reference-backend`. It carries a bearer token to *fetch* the material
/// and never derives anything from it - tokens rotate, and material derived from a rotating
/// value orphans every vault on the next rotation.
final class BackendMaterialProvider: KeyMaterialProviderFfi {

    private let endpoint: URL
    private let bearerToken: () -> String

    init(endpoint: URL, bearerToken: @escaping () -> String) {
        self.endpoint = endpoint
        self.bearerToken = bearerToken
    }

    func getKeyMaterial(ctx: FfiMaterialContext) throws -> FfiKeyMaterial {
        // A production build must refuse plain HTTP outright: the pepper is in the response.
        guard endpoint.scheme == "https" || endpoint.host == "localhost" else {
            throw FfiVaultError.Misconfigured(
                detail: "refusing to fetch key material over plain HTTP"
            )
        }

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(bearerToken())", forHTTPHeaderField: "Authorization")
        // The nonce lets the backend bind its response to this request. envelock does not
        // inspect it; nothing in the key hierarchy depends on it.
        request.httpBody = try JSONSerialization.data(
            withJSONObject: ["nonce": ctx.nonce.base64EncodedString()]
        )

        // envelock already runs this callback on a background thread under its own deadline, so
        // blocking here is correct rather than lazy - and it keeps the provider synchronous,
        // which is what the trait requires.
        let semaphore = DispatchSemaphore(value: 0)
        var payload: Data?
        var status = 0

        URLSession.shared.dataTask(with: request) { data, response, _ in
            payload = data
            status = (response as? HTTPURLResponse)?.statusCode ?? 0
            semaphore.signal()
        }.resume()

        guard semaphore.wait(timeout: .now() + .milliseconds(Int(ctx.deadlineMs))) == .success else {
            throw FfiVaultError.Unavailable
        }

        // 401 is a real denial and counts toward lockout. Everything else is transient and must
        // not, or a backend outage marches a legitimate user into lockout (spec 7.4).
        switch status {
        case 200: break
        case 401, 403: throw FfiVaultError.Denied
        default: throw FfiVaultError.Unavailable
        }

        guard
            let payload,
            let json = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
            let base64 = json["material"] as? String,
            let material = Data(base64Encoded: base64),
            let keyId = json["keyId"] as? String
        else {
            throw FfiVaultError.Misconfigured(detail: "the backend returned a malformed response")
        }

        return FfiKeyMaterial(
            material: material,
            keyId: keyId,
            cacheable: true,
            cacheTtlMs: 30 * 24 * 60 * 60 * 1000
        )
    }
}

/// Supplies the recovery factor.
///
/// A wallet would derive this from its BIP-39 seed with `envelock-bip85`, at a hardened path,
/// and would never let the seed phrase itself reach envelock. This demo uses a fixed key so the
/// recovery path can be exercised without a wallet.
///
/// **The recovery factor is not the host app's PIN** (spec 0). envelock never compares it
/// against a stored value; it is KDF input and nothing else.
final class DemoRecoveryProvider: RecoveryProviderFfi {

    /// A wallet would call `deriveRecoveryKey(seed, 0)` here instead.
    static let demoKey = Data((0..<32).map { UInt8(($0 * 7 + 3) % 256) })

    private(set) var lastReason: FfiRecoveryReason?

    func getRecoveryFactor(reason: FfiRecoveryReason) throws -> FfiRecoveryFactor {
        lastReason = reason
        return .highEntropy(bytes: Self.demoKey)
    }
}

/// Forwards security events into the on-screen log.
final class DemoEventSink: SecurityEventSinkFfi {
    private let onEvent: (String) -> Void

    init(onEvent: @escaping (String) -> Void) {
        self.onEvent = onEvent
    }

    func onEvent(event: FfiSecurityEvent) {
        onEvent("- \(event)")
    }
}
