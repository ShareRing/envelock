package network.sharering.envelock

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.envelock.EnclaveKeyStoreFfi
import uniffi.envelock.FfiHardwareBacking
import uniffi.envelock.FfiKeyMaterial
import uniffi.envelock.FfiMaterialContext
import uniffi.envelock.FfiRecoveryFactor
import uniffi.envelock.FfiRecoveryReason
import uniffi.envelock.FfiVault
import uniffi.envelock.FfiVaultException
import uniffi.envelock.FfiVaultState
import uniffi.envelock.KeyMaterialProviderFfi
import uniffi.envelock.RecoveryProviderFfi
import uniffi.envelock.defaultConfig

/**
 * Bridge conformance for the Kotlin binding.
 *
 * ## Why this does not re-run `vectors.json`
 *
 * Spec 13.1 has every binding check the shared vectors, which is right for a binding that
 * *reimplements* derivation. This one does not - it calls the same Rust core, so running the
 * vectors here would only test Rust through JNA. `vectors.json` stays the contract for anyone
 * reimplementing envelock in another language, enforced in `core/tests/vectors.rs`.
 *
 * What can genuinely break here is the bridge: a mis-mapped exception that turns a cancelled
 * prompt into a lockout-counting denial, a `ByteArray` truncated in conversion, a callback
 * invoked more than once. That is what this covers, using a software key store so it runs on
 * any emulator. [KeystoreKeyStoreTest] covers the real hardware.
 */
@RunWith(AndroidJUnit4::class)
class VaultConformanceTest {

    private lateinit var dir: File
    private lateinit var enclave: SoftwareKeyStore
    private lateinit var material: ScriptedMaterial
    private lateinit var recovery: ScriptedRecovery

    @Before
    fun setUp() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        dir = File(ctx.cacheDir, "envelock-test-${System.nanoTime()}").apply { mkdirs() }
        enclave = SoftwareKeyStore()
        material = ScriptedMaterial()
        recovery = ScriptedRecovery(highEntropyFactor(ByteArray(32) { 0x5a }))
    }

    @After
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun vault(store: EnclaveKeyStoreFfi = enclave): FfiVault {
        val config = defaultConfig("test-provider", dir.absolutePath)
            .copy(argon2MKib = 8u * 1024u, argon2T = 1u)
        return FfiVault(config, store, material, recovery, null)
    }

    @Test
    fun enrollThenReadAndWrite() {
        val v = vault()
        assertEquals(FfiVaultState.NotEnrolled, v.state())

        v.enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
        assertEquals(FfiVaultState.Unlocked, v.state())

        v.put("card:1", "balance:100".toByteArray())
        assertEquals("balance:100", String(v.get("card:1")!!))
        assertEquals(listOf("card:1"), v.list("card:"))

        v.delete("card:1")
        assertNull(v.get("card:1"))
    }

    /** Spec 8.2: a steady-state unlock reads cached material, so the callback does not fire. */
    @Test
    fun unlockAfterRestartIsOffline() {
        vault().enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
        assertEquals(1, material.calls.get())

        material.calls.set(0)
        val v = vault()
        assertEquals(FfiVaultState.Locked, v.state())
        v.unlock()
        assertEquals(FfiVaultState.Unlocked, v.state())
        assertEquals(0, material.calls.get())
    }

    /**
     * A flaky network must never look like a failed authentication. An arbitrary Kotlin
     * exception from a provider becomes `Unavailable`: retryable and uncounted.
     *
     * Without the `From<UnexpectedUniFFICallbackError>` impl on the Rust side, this case does
     * not merely mis-map: it panics across the FFI and takes the process down.
     */
    @Test
    fun unrecognisedKotlinExceptionBecomesUnavailable() {
        val throwing = object : KeyMaterialProviderFfi {
            override fun getKeyMaterial(ctx: FfiMaterialContext): FfiKeyMaterial =
                throw IllegalStateException("socket closed")
        }
        val config = defaultConfig("test-provider", dir.absolutePath).copy(argon2MKib = 8u * 1024u)
        val v = FfiVault(config, enclave, throwing, recovery, null)

        try {
            v.enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
            throw AssertionError("expected Unavailable")
        } catch (e: FfiVaultException.Unavailable) {
            // Correct: retryable and uncounted.
        }
    }

    /** Spec 7.5: a nondeterministic callback is a mismatch, not data corruption. */
    @Test
    fun nondeterministicCallbackReportsAMismatch() {
        vault().enroll(highEntropyFactor(ByteArray(32) { 0x5a }))

        material.material = ByteArray(32) { 0x77 }
        File(dir, "material.cache").delete()

        try {
            vault().unlock()
            throw AssertionError("expected ProviderMaterialMismatch")
        } catch (e: FfiVaultException.ProviderMaterialMismatch) {
            assertTrue(e.message!!.contains("deterministic"))
            assertTrue(e.message!!.contains("PROVIDERS.md"))
        }
    }

    @Test
    fun badMaterialIsRejectedAtEnrollment() {
        material.material = ByteArray(32)
        try {
            vault().enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
            throw AssertionError("expected MaterialRejected")
        } catch (e: FfiVaultException.MaterialRejected) {
            // Correct: `ByteArray(32)` is the all-zero buffer spec 7.2 warns about.
        }
    }

    /** envelock enforces the deadline, so a hung Kotlin callback cannot hang the caller. */
    @Test
    fun hungCallbackTimesOut() {
        material.hangMs = 30_000
        val config = defaultConfig("test-provider", dir.absolutePath)
            .copy(argon2MKib = 8u * 1024u, callbackDeadlineMs = 200u)
        val v = FfiVault(config, enclave, material, recovery, null)

        val started = System.currentTimeMillis()
        try {
            v.enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
            throw AssertionError("expected Unavailable")
        } catch (e: FfiVaultException.Unavailable) {
            assertTrue(System.currentTimeMillis() - started < 10_000)
        }
    }

    /** Spec 11.3: concurrent unlocks coalesce into exactly one callback invocation. */
    @Test
    fun concurrentUnlocksInvokeTheCallbackOnce() {
        vault().enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
        File(dir, "material.cache").delete()
        material.calls.set(0)

        val v = vault()
        val pool = Executors.newFixedThreadPool(8)
        val latch = CountDownLatch(8)
        repeat(8) { pool.submit { try { v.unlock() } finally { latch.countDown() } } }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
        pool.shutdown()

        assertEquals(1, material.calls.get())
        assertEquals(FfiVaultState.Unlocked, v.state())
    }

    /** Spec 8.4: recovery provisions a fresh key and rewraps, so the next unlock is silent. */
    @Test
    fun recoveryOnANewDeviceRewrapsThePrimaryPath() {
        val first = vault()
        first.enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
        first.put("card:1", "balance:100".toByteArray())

        val freshDevice = SoftwareKeyStore()
        val v = vault(freshDevice)
        assertEquals(FfiVaultState.NeedsRecovery, v.state())

        v.unlockWithRecovery()
        assertEquals("balance:100", String(v.get("card:1")!!))
        assertEquals(FfiRecoveryReason.MIGRATE, recovery.lastReason)

        val before = recovery.calls.get()
        v.lock()
        v.unlock()
        assertEquals(before, recovery.calls.get())
    }

    /** 128 bits is not guessable, so a high-entropy vault has no lockout (spec 10). */
    @Test
    fun highEntropyVaultHasNoLockout() {
        vault().enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
        recovery.factor = highEntropyFactor(ByteArray(32) { 0xff.toByte() })
        val v = vault(SoftwareKeyStore())

        repeat(15) {
            try {
                v.unlockWithRecovery()
                throw AssertionError("expected Denied")
            } catch (e: FfiVaultException.Denied) {
                // Expected.
            }
        }

        recovery.factor = highEntropyFactor(ByteArray(32) { 0x5a })
        v.unlockWithRecovery()
        assertEquals(FfiVaultState.Unlocked, v.state())
    }

    @Test
    fun destroyRemovesEverything() {
        val v = vault()
        v.enroll(highEntropyFactor(ByteArray(32) { 0x5a }))
        v.put("card:1", "x".toByteArray())

        v.destroyVault()
        assertEquals(FfiVaultState.NotEnrolled, v.state())
        assertTrue(!File(dir, "envelope.cbor").exists())
    }

    @Test
    fun securityInfoReportsBackingTruthfully() {
        val v = vault()
        v.enroll(highEntropyFactor(ByteArray(32) { 0x5a }))

        val info = v.securityInfo()
        // The double is software-backed and must say so rather than flattering the device.
        assertEquals(FfiHardwareBacking.SOFTWARE, info.hardwareBacking)
        assertEquals("test-provider", info.providerId)
        assertEquals(0u, info.failedAttempts)
        assertNotNull(info.materialCachedUntil)
    }
}

// -------------------------------------------------------------------------------------------
// Test doubles
//
// These live in `androidTest` and nowhere else. Spec 7.2 requires that no flag or hook can
// disable the enclave factor in a shipped build; keeping the software stand-in out of `main` is
// how that holds on this side of the bridge, mirroring `#[cfg(test)]` on the Rust side.
// -------------------------------------------------------------------------------------------

class SoftwareKeyStore : EnclaveKeyStoreFfi {
    private val keys = HashMap<String, ByteArray>()

    override fun createKey(vaultId: ByteArray) {
        keys.getOrPut(vaultId.joinToString("") { "%02x".format(it) }) {
            ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        }
    }

    override fun deviceSecret(vaultId: ByteArray): ByteArray =
        keys[vaultId.joinToString("") { "%02x".format(it) }]
            ?: throw FfiVaultException.Misconfigured("no enclave key")

    override fun keyExists(vaultId: ByteArray) =
        keys.containsKey(vaultId.joinToString("") { "%02x".format(it) })

    override fun deleteKey(vaultId: ByteArray) {
        keys.remove(vaultId.joinToString("") { "%02x".format(it) })
    }

    override fun hardwareBacking() = FfiHardwareBacking.SOFTWARE
}

class ScriptedMaterial : KeyMaterialProviderFfi {
    val calls = AtomicInteger(0)

    /** 32 bytes that pass enrollment validation. */
    var material: ByteArray = ByteArray(32) { ((it * 37 + 11) % 256).toByte() }
    var keyId: String = "v1"
    var cacheable: Boolean = true
    var hangMs: Long = 0

    override fun getKeyMaterial(ctx: FfiMaterialContext): FfiKeyMaterial {
        calls.incrementAndGet()
        if (hangMs > 0) Thread.sleep(hangMs)
        return FfiKeyMaterial(material, keyId, cacheable, 30uL * 24uL * 60uL * 60uL * 1000uL)
    }
}

class ScriptedRecovery(var factor: FfiRecoveryFactor) : RecoveryProviderFfi {
    val calls = AtomicInteger(0)
    var lastReason: FfiRecoveryReason? = null

    override fun getRecoveryFactor(reason: FfiRecoveryReason): FfiRecoveryFactor {
        calls.incrementAndGet()
        lastReason = reason
        return factor
    }
}
