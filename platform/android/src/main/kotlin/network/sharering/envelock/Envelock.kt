package network.sharering.envelock

import android.content.Context
import java.io.File
import uniffi.envelock.EnclaveKeyStoreFfi
import uniffi.envelock.FfiHardwareBacking
import uniffi.envelock.FfiKeyMaterial
import uniffi.envelock.FfiRecoveryFactor
import uniffi.envelock.FfiSecurityEvent
import uniffi.envelock.FfiSecurityInfo
import uniffi.envelock.FfiVault
import uniffi.envelock.FfiVaultConfig
import uniffi.envelock.FfiVaultException
import uniffi.envelock.FfiVaultState
import uniffi.envelock.KeyMaterialProviderFfi
import uniffi.envelock.RecoveryProviderFfi
import uniffi.envelock.SecurityEventSinkFfi
import uniffi.envelock.defaultConfig
import uniffi.envelock.schemeVersion

/**
 * envelock on Android.
 *
 * The generated UniFFI types carry `Ffi` prefixes because they are the bridge's own shapes.
 * These aliases give the consuming SDK names worth reading; they are aliases, not wrappers, so
 * nothing is copied and nothing can drift.
 */
typealias Vault = FfiVault
typealias VaultConfig = FfiVaultConfig
typealias VaultState = FfiVaultState
typealias VaultException = FfiVaultException
typealias RecoveryFactor = FfiRecoveryFactor
typealias KeyMaterial = FfiKeyMaterial
typealias SecurityInfo = FfiSecurityInfo
typealias SecurityEvent = FfiSecurityEvent
typealias HardwareBacking = FfiHardwareBacking
typealias KeyMaterialProvider = KeyMaterialProviderFfi
typealias RecoveryProvider = RecoveryProviderFfi
typealias SecurityEventSink = SecurityEventSinkFfi
typealias EnclaveKeyStore = EnclaveKeyStoreFfi

object Envelock {

    /** Derivation scheme version this build writes (spec 14). Not the library version. */
    val derivationSchemeVersion: UShort get() = schemeVersion()

    /**
     * Build a vault backed by the Android Keystore.
     *
     * @param providerId Stable identifier namespaced into derivation. **Changing it invalidates
     *   every existing vault**, so pick it once.
     * @param directory App-private storage. Defaults to a subdirectory of `filesDir`; do not use
     *   the cache directory, which the OS may evict, destroying the envelope.
     * @param material Your `getKeyMaterial` implementation. Must return identical bytes for a
     *   given key id, every call.
     * @param recovery Supplies the recovery factor. envelock ships no UI, so this is required.
     *
     * ## Lifecycle you must wire up
     *
     * Call [Vault.lock] from `onStop`. Zeroization happens inside the Rust core; dropping a
     * Kotlin reference gives no guarantee the key bytes ever leave memory, because an immutable
     * `ByteArray` may have been copied by the GC (spec 11.3).
     */
    fun createVault(
        context: Context,
        providerId: String,
        material: KeyMaterialProvider,
        recovery: RecoveryProvider,
        events: SecurityEventSink? = null,
        directory: File = File(context.filesDir, "envelock"),
        keyAlias: String = "network.sharering.envelock",
        configure: (VaultConfig) -> VaultConfig = { it },
    ): Pair<Vault, KeystoreKeyStore> {
        directory.mkdirs()
        val config = configure(defaultConfig(providerId, directory.absolutePath))
        val keyStore = KeystoreKeyStore(context, keyAlias)
        return Vault(config, keyStore, material, recovery, events) to keyStore
    }
}

/** A 32-byte high-entropy factor - a BIP-85 child key from the wallet seed, or equivalent. */
fun highEntropyFactor(bytes: ByteArray): RecoveryFactor =
    FfiRecoveryFactor.HighEntropy(bytes)

/**
 * A user-chosen passphrase, stretched with Argon2id.
 *
 * This is **not** the host app's PIN. envelock never receives, requests or stores a host
 * credential (spec 0).
 */
fun passphraseFactor(value: String): RecoveryFactor =
    FfiRecoveryFactor.Passphrase(value)

/** Whether the spec 2.3 security floor actually holds on this device. */
val HardwareBacking.isHardwareBacked: Boolean
    get() = this != FfiHardwareBacking.SOFTWARE
