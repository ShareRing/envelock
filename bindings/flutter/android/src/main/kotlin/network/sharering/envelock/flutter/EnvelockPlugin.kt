package network.sharering.envelock.flutter

import android.content.Context
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.TimeUnit
import network.sharering.envelock.KeystoreKeyStore
import uniffi.envelock.FfiHardwareBacking
import uniffi.envelock.FfiKeyMaterial
import uniffi.envelock.FfiMaterialContext
import uniffi.envelock.FfiMaterialReason
import uniffi.envelock.FfiRecoveryFactor
import uniffi.envelock.FfiRecoveryReason
import uniffi.envelock.FfiSecurityEvent
import uniffi.envelock.FfiVault
import uniffi.envelock.FfiVaultException
import uniffi.envelock.FfiVaultState
import uniffi.envelock.KeyMaterialProviderFfi
import uniffi.envelock.RecoveryProviderFfi
import uniffi.envelock.SecurityEventSinkFfi
import uniffi.envelock.defaultConfig

/**
 * The Flutter plugin.
 *
 * ## How a synchronous Rust callback reaches an asynchronous Dart function
 *
 * The Rust core calls `getKeyMaterial` and waits; a Dart provider returns a `Future`.
 *
 * 1. Every vault method runs on a background executor, so the platform thread is never blocked.
 * 2. When Rust needs material, the native provider posts the Pigeon call to the main thread
 *    (platform channels may only be used there) and blocks *its own* background thread.
 * 3. Dart runs the callback and calls `resolveCallback(requestId, ...)`.
 * 4. The queue hands the value over and the Rust call returns.
 *
 * This cannot deadlock, because step 1 moved the work off the main thread. Blocking the main
 * thread in step 2 would deadlock at once: the thread that has to deliver Dart's answer would
 * be the one waiting for it.
 */
class EnvelockPlugin : FlutterPlugin, EnvelockHostApi {

    private val executor = Executors.newCachedThreadPool()
    private val main = Handler(Looper.getMainLooper())
    private val pending = ConcurrentHashMap<String, SynchronousQueue<CallbackResult>>()

    private lateinit var context: Context
    private var flutterApi: EnvelockFlutterApi? = null

    @Volatile private var vault: FfiVault? = null

    private data class CallbackResult(
        val bytes: ByteArray?,
        val text: String?,
        val errorCode: WireErrorCode?,
        val errorMessage: String?,
    )

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        flutterApi = EnvelockFlutterApi(binding.binaryMessenger)
        EnvelockHostApi.setUp(binding.binaryMessenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        EnvelockHostApi.setUp(binding.binaryMessenger, null)
        flutterApi = null
        releaseAllWaiters()
        vault?.lock()
        vault = null
    }

    // -----------------------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------------------

    override fun create(config: WireVaultConfig, callback: (Result<String>) -> Unit) {
        executor.execute {
            try {
                // Internal storage, never the cache directory: the OS evicts caches under
                // pressure, which would destroy the envelope.
                val directory = config.directory?.let { File(it) }
                    ?: File(context.filesDir, "envelock")
                directory.mkdirs()

                val vaultConfig = defaultConfig(config.providerId, directory.absolutePath).copy(
                    autoLockMs = config.autoLockMs.toULong(),
                    callbackDeadlineMs = config.callbackDeadlineMs.toULong(),
                    destroyAfterAttempts = config.destroyAfterAttempts?.toUInt(),
                )

                vault = FfiVault(
                    vaultConfig,
                    KeystoreKeyStore(context, "network.sharering.envelock.${config.providerId}"),
                    BridgedMaterialProvider(),
                    BridgedRecoveryProvider(),
                    BridgedEventSink(),
                )
                callback(Result.success(directory.absolutePath))
            } catch (e: Throwable) {
                callback(Result.failure(toFlutterError(e)))
            }
        }
    }

    override fun dispose(callback: (Result<Unit>) -> Unit) {
        executor.execute {
            vault?.lock()
            vault = null
            releaseAllWaiters()
            callback(Result.success(Unit))
        }
    }

    // -----------------------------------------------------------------------------------
    // Vault operations
    // -----------------------------------------------------------------------------------

    override fun state(callback: (Result<WireStateResult>) -> Unit) = run(callback) { v ->
        when (val s = v.state()) {
            is FfiVaultState.NotEnrolled -> WireStateResult(WireVaultState.NOT_ENROLLED)
            is FfiVaultState.Locked -> WireStateResult(WireVaultState.LOCKED)
            is FfiVaultState.Unlocked -> WireStateResult(WireVaultState.UNLOCKED)
            is FfiVaultState.NeedsRecovery -> WireStateResult(WireVaultState.NEEDS_RECOVERY)
            is FfiVaultState.LockedOut ->
                WireStateResult(WireVaultState.LOCKED_OUT, s.untilMs.toLong())
        }
    }

    override fun enroll(factor: WireRecoveryFactor, callback: (Result<Unit>) -> Unit) =
        run(callback) { it.enroll(decodeFactor(factor)) }

    override fun unlock(callback: (Result<Unit>) -> Unit) = run(callback) { it.unlock() }

    override fun unlockWithRecovery(callback: (Result<Unit>) -> Unit) =
        run(callback) { it.unlockWithRecovery() }

    override fun changeRecoveryFactor(
        factor: WireRecoveryFactor,
        callback: (Result<Unit>) -> Unit,
    ) = run(callback) { it.changeRecoveryFactor(decodeFactor(factor)) }

    override fun put(recordId: String, value: ByteArray, callback: (Result<Unit>) -> Unit) =
        run(callback) { it.put(recordId, value) }

    override fun get(recordId: String, callback: (Result<ByteArray?>) -> Unit) =
        run(callback) { it.get(recordId) }

    override fun delete(recordId: String, callback: (Result<Unit>) -> Unit) =
        run(callback) { it.delete(recordId) }

    override fun list(prefix: String, callback: (Result<List<String>>) -> Unit) =
        run(callback) { it.list(prefix) }

    override fun lock(callback: (Result<Unit>) -> Unit) = run(callback) { it.lock() }

    override fun destroyVault(callback: (Result<Unit>) -> Unit) = run(callback) { it.destroyVault() }

    override fun securityInfo(callback: (Result<WireSecurityInfo>) -> Unit) = run(callback) { v ->
        val i = v.securityInfo()
        WireSecurityInfo(
            hardwareBacking = wireBacking(i.hardwareBacking),
            providerId = i.providerId,
            keyId = i.keyId,
            recoveryKind =
                if (i.recoveryKind == uniffi.envelock.FfiRecoveryKind.HIGH_ENTROPY)
                    WireRecoveryKind.HIGH_ENTROPY
                else WireRecoveryKind.PASSPHRASE,
            enrolledAt = i.enrolledAt.toLong(),
            failedAttempts = i.failedAttempts.toLong(),
            lockedUntil = i.lockedUntil.toLong(),
            materialCachedUntil = i.materialCachedUntil?.toLong(),
        )
    }

    // -----------------------------------------------------------------------------------
    // Callback plumbing
    // -----------------------------------------------------------------------------------

    override fun resolveCallback(
        requestId: String,
        payload: ByteArray?,
        payloadText: String?,
        errorCode: WireErrorCode?,
        errorMessage: String?,
    ) {
        pending.remove(requestId)
            ?.offer(CallbackResult(payload, payloadText, errorCode, errorMessage))
    }

    /** Ask Dart for something and block this (background) thread until it answers. */
    private fun askDart(
        timeoutMs: Long,
        send: (EnvelockFlutterApi, String) -> Unit,
    ): CallbackResult {
        val api = flutterApi ?: throw FfiVaultException.Misconfigured("the plugin is detached")

        val requestId = UUID.randomUUID().toString()
        val queue = SynchronousQueue<CallbackResult>()
        pending[requestId] = queue

        // Platform channels are main-thread only, and the caller here is a background thread.
        main.post { send(api, requestId) }

        val result = try {
            queue.poll(timeoutMs, TimeUnit.MILLISECONDS)
        } finally {
            pending.remove(requestId)
        } ?: throw FfiVaultException.Unavailable()

        result.errorCode?.let { throw decodeError(it, result.errorMessage) }
        return result
    }

    private fun releaseAllWaiters() {
        pending.keys.toList().forEach {
            pending.remove(it)?.offer(
                CallbackResult(null, null, WireErrorCode.UNAVAILABLE, "the vault was disposed")
            )
        }
    }

    /**
     * Map the taxonomy code Dart sent back onto a typed exception.
     *
     * Unrecognised codes become `Unavailable`: retryable and uncounted (spec 7.4).
     */
    private fun decodeError(code: WireErrorCode, message: String?): FfiVaultException =
        when (code) {
            WireErrorCode.CANCELLED -> FfiVaultException.Cancelled()
            WireErrorCode.DENIED -> FfiVaultException.Denied()
            WireErrorCode.MISCONFIGURED -> FfiVaultException.Misconfigured(message ?: "")
            else -> FfiVaultException.Unavailable()
        }

    // -----------------------------------------------------------------------------------
    // Bridged providers
    // -----------------------------------------------------------------------------------

    private inner class BridgedMaterialProvider : KeyMaterialProviderFfi {
        override fun getKeyMaterial(ctx: FfiMaterialContext): FfiKeyMaterial {
            val reason = when (ctx.reason) {
                FfiMaterialReason.ENROLL -> WireMaterialReason.ENROLL
                FfiMaterialReason.UNLOCK -> WireMaterialReason.UNLOCK
                FfiMaterialReason.ROTATE -> WireMaterialReason.ROTATE
            }

            // A margin over envelock's own deadline; the core is the authority on timing.
            val result = askDart(ctx.deadlineMs.toLong() + 5_000) { api, requestId ->
                api.onKeyMaterialRequested(
                    WireMaterialContext(requestId, reason, ctx.nonce, ctx.deadlineMs.toLong())
                ) {}
            }

            // Dart packs `keyId`, `cacheable` and `cacheTtlMs` NUL-separated into the text field,
            // so the record can be rebuilt without a second round trip. NUL and not a
            // space: a keyId is an arbitrary provider string and may well contain one.
            val bytes = result.bytes
            val parts = result.text?.split("\u0000", limit = 3)
            if (bytes == null || parts == null || parts.size != 3) {
                throw FfiVaultException.Misconfigured("getKeyMaterial returned a malformed result")
            }

            return FfiKeyMaterial(
                bytes,
                parts[0],
                parts[1] == "true",
                parts[2].toULongOrNull() ?: (30uL * 24uL * 60uL * 60uL * 1000uL),
            )
        }
    }

    private inner class BridgedRecoveryProvider : RecoveryProviderFfi {
        override fun getRecoveryFactor(reason: FfiRecoveryReason): FfiRecoveryFactor {
            val wire = when (reason) {
                FfiRecoveryReason.MIGRATE -> WireRecoveryReason.MIGRATE
                FfiRecoveryReason.FALLBACK -> WireRecoveryReason.FALLBACK
                FfiRecoveryReason.CHANGE -> WireRecoveryReason.CHANGE
            }

            // A human is typing or approving; give them real time.
            val result = askDart(300_000) { api, requestId ->
                api.onRecoveryFactorRequested(requestId, wire) {}
            }

            val bytes = result.bytes
            val text = result.text
            return when {
                bytes != null && text == "highEntropy" -> FfiRecoveryFactor.HighEntropy(bytes)
                text != null && text.startsWith("passphrase\u0000") ->
                    FfiRecoveryFactor.Passphrase(text.removePrefix("passphrase\u0000"))
                else -> throw FfiVaultException.Misconfigured(
                    "unrecognised recovery factor encoding"
                )
            }
        }
    }

    private inner class BridgedEventSink : SecurityEventSinkFfi {
        override fun onEvent(event: FfiSecurityEvent) {
            val api = flutterApi ?: return
            val wire = when (event) {
                is FfiSecurityEvent.Enrolled ->
                    WireSecurityEvent("enrolled", hardware = wireBacking(event.hardware))
                is FfiSecurityEvent.Unlocked ->
                    WireSecurityEvent("unlocked", usedCache = event.usedCache)
                is FfiSecurityEvent.RecoveryUsed -> WireSecurityEvent("recoveryUsed")
                is FfiSecurityEvent.UnlockFailed ->
                    WireSecurityEvent("unlockFailed", counted = event.counted)
                is FfiSecurityEvent.ProviderKeyRotated ->
                    WireSecurityEvent("providerKeyRotated", from = event.from, to = event.to)
                is FfiSecurityEvent.MaterialFetched ->
                    WireSecurityEvent("materialFetched", reason = event.reason.name.lowercase())
                is FfiSecurityEvent.MaterialCacheEvicted ->
                    WireSecurityEvent("materialCacheEvicted", reason = event.reason)
                is FfiSecurityEvent.LockedOut ->
                    WireSecurityEvent("lockedOut", untilMs = event.untilMs.toLong())
                is FfiSecurityEvent.VaultDestroyed ->
                    WireSecurityEvent("vaultDestroyed", reason = event.reason)
                is FfiSecurityEvent.HardwareDowngraded ->
                    WireSecurityEvent("hardwareDowngraded", hardware = wireBacking(event.to))
            }
            // Platform channels are main-thread only, and this may fire from a Rust thread.
            main.post { api.onSecurityEvent(wire) {} }
        }
    }

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    private fun <T> run(callback: (Result<T>) -> Unit, body: (FfiVault) -> T) {
        executor.execute {
            val v = vault
            if (v == null) {
                callback(
                    Result.failure(
                        FlutterError("misconfigured", "the vault has not been created", null)
                    )
                )
                return@execute
            }
            try {
                callback(Result.success(body(v)))
            } catch (e: Throwable) {
                callback(Result.failure(toFlutterError(e)))
            }
        }
    }

    /** Surface the taxonomy code, so Dart can branch on it rather than parse a message. */
    private fun toFlutterError(e: Throwable): FlutterError = when (e) {
        is FfiVaultException.Cancelled -> FlutterError("cancelled", "cancelled by user", null)
        is FfiVaultException.Unavailable ->
            FlutterError("unavailable", "key material temporarily unavailable", null)
        is FfiVaultException.Denied -> FlutterError("denied", "access denied", null)
        is FfiVaultException.Misconfigured -> FlutterError("misconfigured", e.message, null)
        is FfiVaultException.ProviderMaterialMismatch ->
            FlutterError("providerMaterialMismatch", e.message, null)
        is FfiVaultException.ProviderKeyRotated ->
            FlutterError("providerKeyRotated", e.message, null)
        is FfiVaultException.MaterialRejected -> FlutterError("materialRejected", e.message, null)
        is FfiVaultException.CorruptData -> FlutterError("corruptData", e.message, null)
        is FfiVaultException.Unexpected -> FlutterError("unexpected", e.message, null)
        else -> FlutterError("unavailable", e.message, null)
    }

    private fun decodeFactor(f: WireRecoveryFactor): FfiRecoveryFactor = when {
        f.highEntropyBytes != null -> FfiRecoveryFactor.HighEntropy(f.highEntropyBytes!!)
        f.passphrase != null -> FfiRecoveryFactor.Passphrase(f.passphrase!!)
        else -> throw FfiVaultException.Misconfigured("the recovery factor was empty")
    }

    private fun wireBacking(b: FfiHardwareBacking): WireHardwareBacking = when (b) {
        FfiHardwareBacking.SECURE_ENCLAVE -> WireHardwareBacking.SECURE_ENCLAVE
        FfiHardwareBacking.STRONG_BOX -> WireHardwareBacking.STRONG_BOX
        FfiHardwareBacking.TEE -> WireHardwareBacking.TEE
        FfiHardwareBacking.SOFTWARE -> WireHardwareBacking.SOFTWARE
    }
}
