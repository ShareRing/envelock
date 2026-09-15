package network.sharering.envelock

import android.app.KeyguardManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.envelock.FfiHardwareBacking

/**
 * Exercises the real Android Keystore.
 *
 * **Requires a device or emulator with a secure lock screen configured.** Every key envelock
 * creates sets `setUserAuthenticationRequired(true)`, which the platform refuses on a device
 * with no PIN, pattern or password. Tests assume-skip rather than fail in that case, so an
 * unconfigured CI emulator stays green while still reporting what it could not cover.
 *
 * **Every test that touches the enclave key raises a prompt**, including `createKey`: the key
 * requires authentication per use regardless of direction, so wrapping the device secret at
 * enrollment prompts exactly as unwrapping it does. Those tests gate on
 * `ENVELOCK_INTERACTIVE=1` and skip otherwise, so CI stays green while still reporting what it
 * could not cover.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreKeyStoreTest {

    private lateinit var context: Context
    private lateinit var store: KeystoreKeyStore
    private lateinit var vaultId: ByteArray

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        assumeTrue(
            "requires a device with a secure lock screen configured",
            keyguard.isDeviceSecure
        )

        store = KeystoreKeyStore(context, keyAlias = "network.sharering.envelock.test")
        vaultId = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
    }

    @After
    fun tearDown() {
        if (::store.isInitialized) runCatching { store.deleteKey(vaultId) }
    }

    @Test
    fun reportsHardwareBackingTruthfully() {
        // Either answer is correct - what matters is that it is never `Software`, and that a
        // StrongBox fallback reports `Tee` rather than claiming a chip the device lacks
        // (spec 6.3, 6.4).
        val backing = store.hardwareBacking()
        assertTrue(
            "expected a hardware backing, got $backing",
            backing == FfiHardwareBacking.STRONG_BOX || backing == FfiHardwareBacking.TEE
        )
        assertTrue(backing.isHardwareBacked)
    }

    /** Skips unless the run can be authenticated by hand. */
    private fun requireInteractive() = assumeTrue(
        "raises a system authentication prompt; run manually with ENVELOCK_INTERACTIVE=1",
        System.getenv("ENVELOCK_INTERACTIVE") == "1"
    )

    @Test
    fun createKeyThenKeyExists() {
        requireInteractive()
        assertFalse(store.keyExists(vaultId))
        store.createKey(vaultId)
        assertTrue(store.keyExists(vaultId))
    }

    /**
     * `keyExists` is called from `state()`, which must never raise an authentication prompt just
     * to answer a status query.
     */
    @Test
    fun keyExistsDoesNotAuthenticate() {
        requireInteractive()
        store.createKey(vaultId)
        repeat(5) { assertTrue(store.keyExists(vaultId)) }
    }

    /**
     * Creating twice must be a no-op. Regenerating would orphan the wrapped secret, and with it
     * the user's data.
     */
    @Test
    fun createKeyIsIdempotent() {
        requireInteractive()
        store.createKey(vaultId)
        store.createKey(vaultId)
        assertTrue(store.keyExists(vaultId))
    }

    @Test
    fun deleteRemovesBothTheKeyAndTheWrappedSecret() {
        requireInteractive()
        store.createKey(vaultId)
        store.deleteKey(vaultId)

        assertFalse(store.keyExists(vaultId))
        runCatching { store.deviceSecret(vaultId) }
            .onSuccess { throw AssertionError("the secret survived deletion") }
    }

    @Test
    fun vaultsAreIsolated() {
        requireInteractive()
        val other = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        try {
            store.createKey(vaultId)
            store.createKey(other)
            assertTrue(store.keyExists(vaultId))
            assertTrue(store.keyExists(other))
        } finally {
            runCatching { store.deleteKey(other) }
        }
    }

    /**
     * Checks the only property the whole key hierarchy depends on: the secret is stable across
     * calls. Costs one prompt for `createKey` and one for each `deviceSecret`.
     */
    @Test
    fun deviceSecretIsStableAcrossCalls() {
        requireInteractive()

        store.createKey(vaultId)
        val first = store.deviceSecret(vaultId)
        assertEquals(32, first.size)
        assertNotEquals(0, first.count { it != 0.toByte() })
        assertArrayEquals(first, store.deviceSecret(vaultId))
    }

    /**
     * Regression test for `setInvalidatedByBiometricEnrollment(false)` (spec 6.3, 13.2).
     *
     * `true` would destroy the key the moment a fingerprint is enrolled - spontaneous data loss
     * for a benign action. This cannot be automated: enroll a new fingerprint between the two
     * runs described below.
     */
    @Test
    fun survivesBiometricEnrollmentChange() {
        assumeTrue(
            "manual: run deviceSecretIsStableAcrossCalls, enroll a new fingerprint, then run " +
                "it again against the same vaultId and confirm the secret is unchanged",
            false
        )
    }
}
