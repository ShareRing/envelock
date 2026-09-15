package network.sharering.envelock.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.TimeUnit
import network.sharering.envelock.KeystoreKeyStore
import org.json.JSONObject
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
 * The React Native module.
 *
 * ## How a synchronous Rust callback reaches an asynchronous JS function
 *
 * The Rust core calls `getKeyMaterial` and waits; a JS provider returns a `Promise`.
 *
 * 1. Every vault method runs on a background executor, so the JS thread is never blocked.
 * 2. When Rust needs material, the native provider emits an event with a request id and blocks
 *    *its own* background thread on a queue.
 * 3. JS runs the callback and calls `resolveCallback(requestId, ...)`.
 * 4. The queue hands the value over and the Rust call returns.
 *
 * This cannot deadlock, because step 1 left the JS thread free. If JS never answers, the wait
 * times out as `unavailable` and envelock's own deadline sits underneath, so a wedged JS thread
 * degrades to a retryable error rather than a hang.
 */
class EnvelockModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val executor = Executors.newCachedThreadPool()
    private val pending = ConcurrentHashMap<String, Waiter>()

    private val vaults = ConcurrentHashMap<String, FfiVault>()

    private class Waiter(val vaultId: String) {
        val queue = SynchronousQueue<CallbackResult>()
    }

    override fun getName() = "RNEnvelock"

    // ---- JSI buffer registry (see cpp/EnvelockJSI.cpp) -------------------------------
    //
    // Bytes move between JavaScript and Rust through native memory rather than base64 strings.
    // That removes an encode and a decode from the JS thread, and - the part that matters -
    // keeps provider material out of immutable JavaScript strings, which cannot be zeroized
    // and linger until the heap is collected.

    private external fun nativeInstall(runtimePointer: Long): Boolean
    private external fun nativeTakeBuffer(token: Long): ByteArray?
    private external fun nativePutBuffer(bytes: ByteArray): Long
    private external fun nativeDropBuffer(token: Long)

    private companion object {
        init {
            System.loadLibrary("envelock_jsi")
        }
    }

    /**
     * Install the JSI host functions. JavaScript calls this once before creating a vault.
     *
     * Synchronous by necessity: the host functions must exist on `global` before any code that
     * uses them runs.
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    fun install(): Boolean {
        val holder = reactContext.javaScriptContextHolder ?: return false
        val pointer = holder.get()
        return if (pointer == 0L) false else nativeInstall(pointer)
    }

    private data class CallbackResult(
        val bytes: ByteArray?,
        val text: String,
        val errorCode: String,
        val errorMessage: String,
    )

    // -----------------------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------------------

    @ReactMethod
    fun create(config: ReadableMap, promise: Promise) = executor.execute {
        try {
            val providerId = config.getString("providerId") ?: ""
            val directory = config.getString("directory")?.let { File(it) }
                // Internal storage, never the cache directory: the OS evicts caches under
                // pressure, which would destroy the envelope.
                ?: File(reactContext.filesDir, "envelock")
            directory.mkdirs()

            var vaultConfig = defaultConfig(providerId, directory.absolutePath)
            if (config.hasKey("autoLockMs")) {
                vaultConfig = vaultConfig.copy(autoLockMs = config.getDouble("autoLockMs").toULong())
            }
            if (config.hasKey("callbackDeadlineMs")) {
                vaultConfig = vaultConfig.copy(
                    callbackDeadlineMs = config.getDouble("callbackDeadlineMs").toULong()
                )
            }
            // `null` from JS disables destruction entirely; anything else is the limit.
            vaultConfig = vaultConfig.copy(
                destroyAfterAttempts =
                    if (config.hasKey("destroyAfterAttempts") && !config.isNull("destroyAfterAttempts"))
                        config.getDouble("destroyAfterAttempts").toUInt()
                    else null
            )

            val vaultId = UUID.randomUUID().toString()
            vaults[vaultId] = FfiVault(
                vaultConfig,
                KeystoreKeyStore(reactContext, "network.sharering.envelock.$providerId"),
                BridgedMaterialProvider(vaultId),
                BridgedRecoveryProvider(vaultId),
                BridgedEventSink(vaultId),
            )
            promise.resolve("$vaultId ${directory.absolutePath}")
        } catch (e: Throwable) {
            reject(promise, e)
        }
    }

    @ReactMethod
    fun destroyInstance(vaultId: String, promise: Promise) = executor.execute {
        vaults.remove(vaultId)?.lock()
        pending.entries.filter { it.value.vaultId == vaultId }.forEach { (id, _) ->
            pending.remove(id)?.queue?.offer(
                CallbackResult(null, "", "unavailable", "the vault was disposed")
            )
        }
        promise.resolve(null)
    }

    // -----------------------------------------------------------------------------------
    // Vault operations
    // -----------------------------------------------------------------------------------

    @ReactMethod
    fun state(vaultId: String, promise: Promise) = run(vaultId, promise) { v ->
        when (val s = v.state()) {
            is FfiVaultState.NotEnrolled -> "not_enrolled"
            is FfiVaultState.Locked -> "locked"
            is FfiVaultState.Unlocked -> "unlocked"
            is FfiVaultState.NeedsRecovery -> "needs_recovery"
            is FfiVaultState.LockedOut -> "locked_out:${s.untilMs}"
        }
    }

    /**
     * A high-entropy factor arrives as a buffer token; a passphrase is inherently a string, so
     * there is nothing to gain by tokenizing it.
     */
    @ReactMethod
    fun enroll(
        vaultId: String,
        kind: String,
        token: Double,
        passphrase: String,
        promise: Promise,
    ) = run(vaultId, promise) { it.enroll(decodeFactor(kind, token, passphrase)); null }

    @ReactMethod
    fun unlock(vaultId: String, promise: Promise) = run(vaultId, promise) { it.unlock(); null }

    @ReactMethod
    fun unlockWithRecovery(vaultId: String, promise: Promise) =
        run(vaultId, promise) { it.unlockWithRecovery(); null }

    @ReactMethod
    fun changeRecoveryFactor(
        vaultId: String,
        kind: String,
        token: Double,
        passphrase: String,
        promise: Promise,
    ) = run(vaultId, promise) { it.changeRecoveryFactor(decodeFactor(kind, token, passphrase)); null }

    /** `token` names bytes JavaScript already handed to the JSI buffer registry. */
    @ReactMethod
    fun put(vaultId: String, recordId: String, token: Double, promise: Promise) =
        run(vaultId, promise) { v ->
        val bytes = nativeTakeBuffer(token.toLong())
            ?: throw FfiVaultException.Misconfigured("unknown or already-redeemed buffer token")
        try {
            v.put(recordId, bytes)
        } finally {
            bytes.fill(0)
        }
        null
    }

    /** Returns a token JavaScript redeems for an `ArrayBuffer`, or `0` for a missing record. */
    @ReactMethod
    fun get(vaultId: String, recordId: String, promise: Promise) = run(vaultId, promise) { v ->
        v.get(recordId)?.let { nativePutBuffer(it).toDouble() } ?: 0.0
    }

    @ReactMethod
    fun remove(vaultId: String, recordId: String, promise: Promise) =
        run(vaultId, promise) { it.delete(recordId); null }

    @ReactMethod
    fun list(vaultId: String, prefix: String, promise: Promise) = run(vaultId, promise) { v ->
        Arguments.fromList(v.list(prefix))
    }

    @ReactMethod
    fun lock(vaultId: String, promise: Promise) = run(vaultId, promise) { it.lock(); null }

    @ReactMethod
    fun destroyVault(vaultId: String, promise: Promise) =
        run(vaultId, promise) { it.destroyVault(); null }

    @ReactMethod
    fun securityInfo(vaultId: String, promise: Promise) = run(vaultId, promise) { v ->
        val i = v.securityInfo()
        JSONObject().apply {
            put("hardwareBacking", name(i.hardwareBacking))
            put("providerId", i.providerId)
            put("keyId", i.keyId)
            put("recoveryKind", i.recoveryKind.name.lowercase())
            put("enrolledAt", i.enrolledAt.toLong())
            put("failedAttempts", i.failedAttempts.toLong())
            put("lockedUntil", i.lockedUntil.toLong())
            put("materialCachedUntil", i.materialCachedUntil?.toLong() ?: JSONObject.NULL)
        }.toString()
    }

    // -----------------------------------------------------------------------------------
    // Callback plumbing
    // -----------------------------------------------------------------------------------

    @ReactMethod
    fun resolveCallback(
        requestId: String,
        token: Double,
        text: String,
        errorCode: String,
        errorMessage: String,
    ) {
        val waiter = pending.remove(requestId)
        if (waiter == null) {
            // Nobody is waiting - the request timed out or the vault was disposed. The payload
            // must still be released, or an abandoned secret sits in memory until exit.
            if (token != 0.0) nativeDropBuffer(token.toLong())
            return
        }
        val bytes = if (token == 0.0) null else nativeTakeBuffer(token.toLong())
        waiter.queue.offer(CallbackResult(bytes, text, errorCode, errorMessage))
    }

    // Required by NativeEventEmitter on the JS side; the work is done by RN itself.
    @ReactMethod fun addListener(eventName: String) = Unit
    @ReactMethod fun removeListeners(count: Double) = Unit

    /** Ask JS for something and block this (background) thread until it answers. */
    private fun askJs(
        vaultId: String,
        event: String,
        body: WritableMap,
        timeoutMs: Long,
    ): CallbackResult {
        val requestId = UUID.randomUUID().toString()
        val waiter = Waiter(vaultId)
        pending[requestId] = waiter

        body.putString("requestId", requestId)
        // JavaScript dispatches on this: one router for the process, not a listener per vault.
        body.putString("vaultId", vaultId)
        reactContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(event, body)

        val result = try {
            waiter.queue.poll(timeoutMs, TimeUnit.MILLISECONDS)
        } finally {
            pending.remove(requestId)
        } ?: throw FfiVaultException.Unavailable()

        if (result.errorCode.isNotEmpty()) throw decodeError(result.errorCode, result.errorMessage)
        return result
    }

    /**
     * Map the taxonomy code JS sent back onto a typed exception.
     *
     * Unrecognised codes become `Unavailable`: retryable and uncounted (spec 7.4).
     */
    private fun decodeError(code: String, message: String): FfiVaultException = when (code) {
        "cancelled" -> FfiVaultException.Cancelled()
        "denied" -> FfiVaultException.Denied()
        "misconfigured" -> FfiVaultException.Misconfigured(message)
        else -> FfiVaultException.Unavailable()
    }

    // -----------------------------------------------------------------------------------
    // Bridged providers
    // -----------------------------------------------------------------------------------

    private inner class BridgedMaterialProvider(private val vaultId: String) :
        KeyMaterialProviderFfi {
        override fun getKeyMaterial(ctx: FfiMaterialContext): FfiKeyMaterial {
            val body = Arguments.createMap().apply {
                putString(
                    "reason",
                    when (ctx.reason) {
                        FfiMaterialReason.ENROLL -> "enroll"
                        FfiMaterialReason.UNLOCK -> "unlock"
                        FfiMaterialReason.ROTATE -> "rotate"
                    }
                )
                // The nonce goes out as a token too, so nothing in this exchange is a string.
                putDouble("nonceToken", nativePutBuffer(ctx.nonce).toDouble())
                putDouble("deadlineMs", ctx.deadlineMs.toDouble())
            }

            // A margin over envelock's own deadline: the core is the authority on timing, and
            // this only prevents a silent JS thread from wedging a native one forever.
            val answer =
                askJs(vaultId, "envelock:getKeyMaterial", body, ctx.deadlineMs.toLong() + 5_000)

            // JS packs `keyId cacheable cacheTtlMs` into the text field; the material itself
            // came back as bytes.
            val bytes = answer.bytes
            val parts = answer.text.split(" ", limit = 3)
            if (bytes == null || parts.size != 3) {
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

    private inner class BridgedRecoveryProvider(private val vaultId: String) :
        RecoveryProviderFfi {
        override fun getRecoveryFactor(reason: FfiRecoveryReason): FfiRecoveryFactor {
            val body = Arguments.createMap().apply {
                putString(
                    "reason",
                    when (reason) {
                        FfiRecoveryReason.MIGRATE -> "migrate"
                        FfiRecoveryReason.FALLBACK -> "fallback"
                        FfiRecoveryReason.CHANGE -> "change"
                    }
                )
            }
            // A human is typing or approving; give them real time.
            val answer = askJs(vaultId, "envelock:getRecoveryFactor", body, 300_000)
            val bytes = answer.bytes
            return when {
                answer.text == "highEntropy" && bytes != null ->
                    FfiRecoveryFactor.HighEntropy(bytes)
                answer.text.startsWith("passphrase ") ->
                    FfiRecoveryFactor.Passphrase(answer.text.removePrefix("passphrase "))
                else -> throw FfiVaultException.Misconfigured(
                    "unrecognised recovery factor encoding"
                )
            }
        }
    }

    private inner class BridgedEventSink(private val vaultId: String) : SecurityEventSinkFfi {
        override fun onEvent(event: FfiSecurityEvent) {
            val body = Arguments.createMap()
            when (event) {
                is FfiSecurityEvent.Enrolled -> {
                    body.putString("type", "enrolled")
                    body.putString("hardware", name(event.hardware))
                }
                is FfiSecurityEvent.Unlocked -> {
                    body.putString("type", "unlocked")
                    body.putBoolean("usedCache", event.usedCache)
                }
                is FfiSecurityEvent.RecoveryUsed -> body.putString("type", "recoveryUsed")
                is FfiSecurityEvent.UnlockFailed -> {
                    body.putString("type", "unlockFailed")
                    body.putBoolean("counted", event.counted)
                }
                is FfiSecurityEvent.ProviderKeyRotated -> {
                    body.putString("type", "providerKeyRotated")
                    body.putString("from", event.from)
                    body.putString("to", event.to)
                }
                is FfiSecurityEvent.MaterialFetched -> {
                    body.putString("type", "materialFetched")
                    body.putString("reason", event.reason.name.lowercase())
                }
                is FfiSecurityEvent.MaterialCacheEvicted -> {
                    body.putString("type", "materialCacheEvicted")
                    body.putString("reason", event.reason)
                }
                is FfiSecurityEvent.LockedOut -> {
                    body.putString("type", "lockedOut")
                    body.putDouble("untilMs", event.untilMs.toDouble())
                }
                is FfiSecurityEvent.VaultDestroyed -> {
                    body.putString("type", "vaultDestroyed")
                    body.putString("reason", event.reason)
                }
                is FfiSecurityEvent.HardwareDowngraded -> {
                    body.putString("type", "hardwareDowngraded")
                    body.putString("to", name(event.to))
                }
            }
            body.putString("vaultId", vaultId)
            reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
                .emit("envelock:securityEvent", body)
        }
    }

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    private fun run(vaultId: String, promise: Promise, body: (FfiVault) -> Any?) {
        executor.execute {
            val v = vaults[vaultId]
            if (v == null) {
                promise.reject(
                    "misconfigured",
                    "no such vault: it was disposed, or never created",
                )
                return@execute
            }
            try {
                promise.resolve(body(v))
            } catch (e: Throwable) {
                reject(promise, e)
            }
        }
    }

    /** Reject with the taxonomy code, so JS can branch on it rather than parse a message. */
    private fun reject(promise: Promise, e: Throwable) = when (e) {
        is FfiVaultException.Cancelled -> promise.reject("cancelled", "cancelled by user", e)
        is FfiVaultException.Unavailable ->
            promise.reject("unavailable", "key material temporarily unavailable", e)
        is FfiVaultException.Denied -> promise.reject("denied", "access denied", e)
        is FfiVaultException.Misconfigured -> promise.reject("misconfigured", e.message, e)
        is FfiVaultException.ProviderMaterialMismatch ->
            promise.reject("providerMaterialMismatch", e.message, e)
        is FfiVaultException.ProviderKeyRotated -> promise.reject("providerKeyRotated", e.message, e)
        is FfiVaultException.MaterialRejected -> promise.reject("materialRejected", e.message, e)
        is FfiVaultException.CorruptData -> promise.reject("corruptData", e.message, e)
        is FfiVaultException.Unexpected -> promise.reject("unexpected", e.message, e)
        else -> promise.reject("unavailable", e.message, e)
    }

    private fun decodeFactor(kind: String, token: Double, passphrase: String): FfiRecoveryFactor =
        when (kind) {
            "highEntropy" -> FfiRecoveryFactor.HighEntropy(
                nativeTakeBuffer(token.toLong())
                    ?: throw FfiVaultException.Misconfigured(
                        "unknown or already-redeemed buffer token"
                    )
            )
            "passphrase" -> FfiRecoveryFactor.Passphrase(passphrase)
            else -> throw FfiVaultException.Misconfigured("unrecognised recovery factor kind")
        }

    private fun name(b: FfiHardwareBacking) = when (b) {
        FfiHardwareBacking.SECURE_ENCLAVE -> "secureEnclave"
        FfiHardwareBacking.STRONG_BOX -> "strongBox"
        FfiHardwareBacking.TEE -> "tee"
        FfiHardwareBacking.SOFTWARE -> "software"
    }
}
