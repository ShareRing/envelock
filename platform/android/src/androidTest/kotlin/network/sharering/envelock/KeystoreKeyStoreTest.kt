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
 * Tests that would raise a biometric prompt cannot run unattended and are marked as such.
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

    @Test
    fun createKeyThenKeyExists() {
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
        store.createKey(vaultId)
        repeat(5) { assertTrue(store.keyExists(vaultId)) }
    }

    /**
     * Creating twice must be a no-op. Regenerating would orphan the wrapped secret, and with it
     * the user's data.
     */
    @Test
    fun createKeyIsIdempotent() {
        store.createKey(vaultId)
        store.createKey(vaultId)
        assertTrue(store.keyExists(vaultId))
    }

    @Test
    fun deleteRemovesBothTheKeyAndTheWrappedSecret() {
        store.createKey(vaultId)
        store.deleteKey(vaultId)

        assertFalse(store.keyExists(vaultId))
        runCatching { store.deviceSecret(vaultId) }
            .onSuccess { throw AssertionError("the secret survived deletion") }
    }

    @Test
    fun vaultsAreIsolated() {
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
     * Unsealing the device secret raises the OS prompt, so this cannot run unattended.
     *
     * Enable it on a device where you can authenticate by hand. It checks the only property the
     * whole key hierarchy depends on: that the secret is stable across calls.
     */
    @Test
    fun deviceSecretIsStableAcrossCalls() {
        assumeTrue(
            "raises a biometric prompt; run manually with ENVELOCK_INTERACTIVE=1",
            System.getenv("ENVELOCK_INTERACTIVE") == "1"
        )

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
