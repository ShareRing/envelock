package network.sharering.envelock

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.envelock.EnclaveKeyStoreFfi
import uniffi.envelock.FfiHardwareBacking
import uniffi.envelock.FfiVaultException

/**
 * The Android half of envelock's security floor (spec 6.3, 7.2).
 *
 * An AES-256 key is generated inside the Android Keystore and never leaves it. At enrollment a
 * random 32-byte device secret is wrapped with that key; every unlock unwraps it, which the OS
 * gates behind biometrics or the device credential. That prompt is the single prompt of a
 * steady-state unlock.
 *
 * ## This class performs no key derivation
 *
 * It unwraps bytes and returns them. The core HKDFs them with a domain-separated string. If this
 * class derived instead, the same logic would also live in Swift, and one of them would
 * eventually differ by a byte - leaving a user who restored onto the other platform unable to
 * decrypt (spec 3.2).
 *
 * ## `setInvalidatedByBiometricEnrollment(false)`
 *
 * `true` destroys the key the moment the user enrolls a new fingerprint, which is spontaneous
 * data loss for a benign action. The recovery path, not key invalidation, is the right answer to
 * a credential change (spec 6.3). If a security review demands `true`, shipping it also means
 * shipping a pre-invalidation warning and a forced re-enrollment flow - decide before launch.
 *
 * ## `AUTH_DEVICE_CREDENTIAL` is not optional
 *
 * A server-side login satisfies no OS gate. Without device-credential
 * authentication, a user who has enrolled no biometrics could not unlock at all (spec 6.3).
 *
 * @param context Application context, used only to locate app-private storage.
 * @param keyAlias Prefix for Keystore aliases. The consuming SDK sets this so two SDKs in one
 *   app cannot collide.
 * @param authValiditySeconds `0` requires authentication for every use - the strictest setting.
 *   A positive value lets one authentication cover a burst, at the cost of a window in which no
 *   prompt appears.
 */
class KeystoreKeyStore(
    context: Context,
    private val keyAlias: String,
    private val authValiditySeconds: Int = 0,
) : EnclaveKeyStoreFfi {

    private val appContext = context.applicationContext
    private val lock = Any()

    /** Set once the first key is created, so `hardwareBacking()` reports what actually happened. */
    @Volatile
    private var strongBoxAvailable: Boolean? = null

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val GCM_IV_BYTES = 12
        const val SECRET_BYTES = 32
        const val WRAPPED_DIR = "envelock-keystore"
    }

    // ---------------------------------------------------------------------------------------
    // EnclaveKeyStoreFfi
    // ---------------------------------------------------------------------------------------

    override fun createKey(vaultId: ByteArray) = synchronized(lock) {
        // Idempotent: enrollment may be retried after a transient failure, and regenerating
        // would orphan the wrapped secret and with it the user's data.
        if (keystoreKey(vaultId) != null && wrappedFile(vaultId).exists()) return@synchronized

        deleteEverything(vaultId)
        val key = generateKey(vaultId)

        val secret = ByteArray(SECRET_BYTES).also { SecureRandom().nextBytes(it) }
        try {
            // Encryption uses the key without authenticating, because the key was just created
            // in an authenticated context. Only decryption raises the prompt.
            val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
            val ciphertext = cipher.doFinal(secret)
            writeAtomically(wrappedFile(vaultId), cipher.iv + ciphertext)
        } finally {
            secret.fill(0)
        }
    }

    override fun deviceSecret(vaultId: ByteArray): ByteArray {
        val key = keystoreKey(vaultId)
            ?: throw FfiVaultException.Misconfigured("no enclave key exists for this vault")
        val blob = wrappedFile(vaultId).takeIf { it.exists() }?.readBytes()
            ?: throw FfiVaultException.Misconfigured("the wrapped device secret is missing")
        if (blob.size <= GCM_IV_BYTES) {
            throw FfiVaultException.CorruptData("the wrapped device secret is truncated")
        }

        val iv = blob.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)

        return try {
            Cipher.getInstance(TRANSFORMATION)
                .apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv)) }
                .doFinal(ciphertext)
        } catch (e: UserNotAuthenticatedException) {
            // The user has not authenticated within the validity window. This is normal, and
            // must not count toward lockout (spec 7.4) - the caller re-prompts.
            throw FfiVaultException.Cancelled()
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            // Reachable if a future build sets `setInvalidatedByBiometricEnrollment(true)`, or
            // if the user removed their device credential entirely. Recovery is the answer.
            throw FfiVaultException.Misconfigured(
                "the enclave key was invalidated by a credential change; use the recovery path"
            )
        } catch (e: Exception) {
            throw FfiVaultException.CorruptData("could not unwrap the device secret: ${e.message}")
        }
    }

    override fun keyExists(vaultId: ByteArray): Boolean = synchronized(lock) {
        // Deliberately does not authenticate: this is called from `state()`, which must never
        // raise a biometric prompt just to answer a status query.
        keystoreKey(vaultId) != null && wrappedFile(vaultId).exists()
    }

    override fun deleteKey(vaultId: ByteArray) = synchronized(lock) {
        deleteEverything(vaultId)
    }

    override fun hardwareBacking(): FfiHardwareBacking = when (strongBoxAvailable) {
        true -> FfiHardwareBacking.STRONG_BOX
        // A key generated without StrongBox is still Keystore-backed, which on any modern
        // device means the TEE.
        false -> FfiHardwareBacking.TEE
        // No key created yet: report what this device could provide.
        null -> if (supportsStrongBox()) FfiHardwareBacking.STRONG_BOX else FfiHardwareBacking.TEE
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    private fun generateKey(vaultId: ByteArray): SecretKey {
        // StrongBox first; fall back to the TEE and report the downgrade truthfully rather than
        // claiming a posture the device does not have (spec 6.3, 6.4).
        if (supportsStrongBox()) {
            try {
                val key = generateKey(vaultId, strongBox = true)
                strongBoxAvailable = true
                return key
            } catch (e: StrongBoxUnavailableException) {
                // Expected on devices without a dedicated security chip.
            }
        }
        strongBoxAvailable = false
        return generateKey(vaultId, strongBox = false)
    }

    @Suppress("DEPRECATION")
    private fun generateKey(vaultId: ByteArray, strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            alias(vaultId),
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                authValiditySeconds,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            // API 23-29. `-1` means "authentication required for every use" (spec 6.3).
            builder.setUserAuthenticationValidityDurationSeconds(
                if (authValiditySeconds == 0) -1 else authValiditySeconds
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(false)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            if (strongBox) builder.setIsStrongBoxBacked(true)
        }

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    private fun supportsStrongBox(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )

    private fun keystoreKey(vaultId: ByteArray): SecretKey? = try {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }
            .getKey(alias(vaultId), null) as? SecretKey
    } catch (e: Exception) {
        null
    }

    private fun alias(vaultId: ByteArray) = "$keyAlias.${vaultId.toHex()}"

    private fun wrappedFile(vaultId: ByteArray) =
        File(File(appContext.filesDir, WRAPPED_DIR).apply { mkdirs() }, "${vaultId.toHex()}.bin")

    /** Write via a temporary file and rename, so a crash mid-write cannot truncate the secret. */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.outputStream().use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw FfiVaultException.CorruptData("could not store the wrapped device secret")
        }
    }

    private fun deleteEverything(vaultId: ByteArray) {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias(vaultId))
        } catch (e: Exception) {
            // Already gone, which is the desired end state.
        }
        wrappedFile(vaultId).delete()
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }
}
