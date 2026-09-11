package network.sharering.envelock.demo

import android.content.Context
import java.io.File
import java.security.SecureRandom
import network.sharering.envelock.Envelock
import network.sharering.envelock.KeyMaterialProvider
import network.sharering.envelock.RecoveryFactor
import network.sharering.envelock.RecoveryProvider
import network.sharering.envelock.SecurityEventSink
import network.sharering.envelock.Vault
import network.sharering.envelock.VaultState
import network.sharering.envelock.passphraseFactor
import org.json.JSONArray
import org.json.JSONObject
import uniffi.envelock.FfiRecoveryReason
import uniffi.envelock.FfiVaultException
import uniffi.envelock.FfiVaultState

/**
 * A stand-in for a host SDK with envelock baked in, the layer an external app installs.
 *
 * envelock lives *inside* this file, not in the app above it. The app never sees [Vault] and
 * never learns a state machine exists. It gets [initialize], [destroy], [getDocument] and
 * [getRecoveryFactor], plus [lock], because Android has no lifecycle hook the library can
 * install for you (spec 11.3).
 *
 * Nothing here is part of the library. [MainActivity] drives the same vault directly, which is
 * the other half of the picture.
 */

/** What the app hands the SDK. Everything envelock-shaped is here, and nothing else. */
class SdkVaultOptions(
    /** Namespaced into every derivation. **Changing it invalidates every existing vault.** */
    val providerId: String,
    /** Must return byte-identical material every call. */
    val material: KeyMaterialProvider,
    /**
     * Asked for the 12 words on a device that has never held them: a restored backup, a new
     * phone. Called on a background thread from the Rust core and **must block** until the user
     * answers, or throw [FfiVaultException.Cancelled] if they dismiss the prompt.
     */
    val promptRecoveryPhrase: (FfiRecoveryReason) -> String,
    val events: SecurityEventSink? = null,
)

class SdkOptions(
    val appId: String,
    val vaultOptions: SdkVaultOptions,
    /**
     * Where a document comes from the first time. After that it is served from the vault,
     * offline, with no network call - that is the point of the vault.
     */
    val fetchDocument: (String) -> ByteArray,
)

/** What the SDK does next, given what the vault says it is. */
enum class SdkStep { READY, ENROLL, UNLOCK, RECOVER, LOCKED_OUT }

/**
 * Pulled out as a pure function so the routing can be reasoned about on its own; the vault's
 * own states never reach the app above.
 */
fun stepFor(state: VaultState): SdkStep = when (state) {
    is FfiVaultState.Unlocked -> SdkStep.READY
    is FfiVaultState.NotEnrolled -> SdkStep.ENROLL
    is FfiVaultState.Locked -> SdkStep.UNLOCK
    is FfiVaultState.NeedsRecovery -> SdkStep.RECOVER
    is FfiVaultState.LockedOut -> SdkStep.LOCKED_OUT
}

class ShareRingVaultSdk private constructor(
    private val options: SdkOptions,
    private val wordlist: List<String>,
) {

    private lateinit var vault: Vault

    /**
     * Held in memory only. Persisted inside the vault, never beside it: app storage is
     * plaintext on a rooted device and the phrase opens everything.
     */
    @Volatile
    private var phrase: String? = null

    companion object {
        private const val PHRASE_RECORD = "sys:recovery-phrase"

        /**
         * Opens the vault and enrolls if this is the first run.
         *
         * Blocking: enrollment prompts for enclave consent. Call it off the main thread.
         */
        fun initialize(context: Context, options: SdkOptions): ShareRingVaultSdk {
            val sdk = ShareRingVaultSdk(options, loadWordlist(context))
            val v = options.vaultOptions

            val (vault, _) = Envelock.createVault(
                context = context,
                providerId = v.providerId,
                // Its own directory, so the SDK's vault and a vault the app opens itself never
                // fight over one envelope.
                directory = File(context.filesDir, "sharering-sdk"),
                material = v.material,
                // The app supplies material; the SDK owns recovery. This is why there is no
                // recovery provider in `SdkVaultOptions`.
                recovery = sdk.SdkRecoveryProvider(),
                events = v.events,
            )
            sdk.vault = vault

            sdk.ready()
            return sdk
        }

        /**
         * The BIP-39 English wordlist, shared with the iOS and React Native examples through
         * `examples/shared` so there is exactly one copy of it.
         */
        private fun loadWordlist(context: Context): List<String> {
            val json = context.assets.open("bip39-english.json").use { it.readBytes() }
            val array = JSONArray(String(json))
            return List(array.length()) { array.getString(it) }
        }
    }

    /**
     * The 12 words. Show them once at setup and let the user write them down.
     *
     * Reading them needs an unlocked vault (they are stored in it) so this costs a biometric
     * prompt on a locked session, which is the correct price for revealing them.
     */
    fun getRecoveryFactor(): String {
        phrase?.let { return it }

        ready()
        val stored = vault.get(PHRASE_RECORD)
            ?: throw FfiVaultException.CorruptData(
                "the vault is enrolled but holds no recovery phrase"
            )
        return String(stored).also { phrase = it }
    }

    /** Cached in the vault after the first fetch; every later call is offline. */
    fun getDocument(documentId: String): JSONObject {
        ready()

        val id = "doc:$documentId"
        vault.get(id)?.let { return JSONObject(String(it)) }

        val fetched = options.fetchDocument(documentId)
        vault.put(id, fetched)
        return JSONObject(String(fetched))
    }

    /**
     * Zeroize the in-memory key. Wire this to `onStop`: Android gives the library no lifecycle
     * hook of its own, and zeroization has to happen inside the Rust core because dropping a
     * Kotlin reference guarantees nothing (spec 11.3).
     */
    fun lock() = vault.lock()

    /**
     * Irreversible: enclave key, envelope, cache and every document. The 12 words do not bring
     * this back - nothing does.
     */
    fun destroy() {
        vault.destroyVault()
        phrase = null
    }

    /** Drive the vault to `Unlocked`, whatever it currently is. */
    private fun ready() {
        val state = vault.state()

        when (stepFor(state)) {
            SdkStep.READY -> return

            SdkStep.ENROLL -> {
                // A passphrase factor, so the spec 10 backoff ladder applies and 11 failed
                // attempts destroy the vault. A wallet should derive 32 bytes from its seed with
                // envelock-bip85 and enroll a high-entropy factor instead, which has no ladder.
                val generated = generateRecoveryPhrase()
                vault.enroll(passphraseFactor(generated))
                phrase = generated

                // Enrollment is atomic: a vault enrolled with a phrase that never reached
                // storage is unopenable by anyone, so tear it down rather than leave that
                // behind.
                runCatching { vault.put(PHRASE_RECORD, generated.toByteArray()) }
                    .onFailure {
                        vault.destroyVault()
                        phrase = null
                        throw it
                    }
            }

            SdkStep.UNLOCK -> vault.unlock()

            // Rewraps the primary path in the same operation, so the next unlock is
            // biometric-only.
            SdkStep.RECOVER -> vault.unlockWithRecovery()

            // Retrying here would burn an attempt against a ladder that is already throttling.
            SdkStep.LOCKED_OUT -> {
                val until = (state as FfiVaultState.LockedOut).untilMs
                throw FfiVaultException.Misconfigured(
                    "too many failed recovery attempts; retry after $until"
                )
            }
        }
    }

    /** 12 words drawn from the BIP-39 English list with a CSPRNG: 132 bits. */
    private fun generateRecoveryPhrase(): String {
        val random = SecureRandom()
        return (0 until 12).joinToString(" ") { wordlist[random.nextInt(wordlist.size)] }
    }

    /** Serves the recovery factor from the phrase the SDK holds, or asks the app for it. */
    private inner class SdkRecoveryProvider : RecoveryProvider {
        override fun getRecoveryFactor(reason: FfiRecoveryReason): RecoveryFactor {
            val typed = (phrase ?: options.vaultOptions.promptRecoveryPhrase(reason))
                .trim()
                .split(Regex("\\s+"))

            // A mistyped word never reaches the KDF. Not `Denied`: nothing was verified, so this
            // must not spend one of the 11 attempts (spec 7.4).
            if (typed.size != 12 || typed.any { it !in wordlist }) {
                throw FfiVaultException.Cancelled()
            }

            return passphraseFactor(typed.joinToString(" ").also { phrase = it })
        }
    }
}
