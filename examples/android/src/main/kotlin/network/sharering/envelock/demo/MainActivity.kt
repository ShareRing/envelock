package network.sharering.envelock.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import network.sharering.envelock.Envelock
import network.sharering.envelock.KeystoreKeyStore
import network.sharering.envelock.SecurityEventSink
import network.sharering.envelock.Vault
import network.sharering.envelock.VaultState
import network.sharering.envelock.highEntropyFactor
import network.sharering.envelock.isHardwareBacked
import java.security.KeyStore
import uniffi.envelock.FfiVaultException
import uniffi.envelock.FfiVaultState

/**
 * Delete this app's enclave keys, to demonstrate the recovery path.
 *
 * Lives in the example rather than in envelock: production code has no business bulk-deleting
 * keys, and adding an API for it would be an API that exists only to destroy user data.
 *
 * Enumerating the alias prefix is what `envelock` itself uses per vault
 * (`"$keyAlias.$vaultIdHex"`), so this finds every vault the demo created.
 */
private fun deleteDemoKeystoreEntries(prefix: String = "network.sharering.envelock"): Int {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val doomed = store.aliases().toList().filter { it.startsWith(prefix) }
    doomed.forEach { runCatching { store.deleteEntry(it) } }
    return doomed.size
}

/**
 * envelock on native Android.
 *
 * Walks the whole lifecycle so each step can be seen in isolation: enroll, lock, unlock, write,
 * read, recover, destroy. The log pane shows what actually happened, including which errors are
 * benign.
 *
 * ## What to watch for
 *
 * - **Unlock prompts once**, then reads records with no further prompt and no network.
 * - **Cancelling the biometric prompt** produces `Cancelled`, not a lockout. Dismissing a
 *   prompt is normal behaviour, not a failed authentication.
 * - **"Simulate new device"** deletes the enclave key. The state becomes `NeedsRecovery`, and
 *   recovery rewraps so the *next* unlock is biometric-only again.
 */
class MainActivity : ComponentActivity() {

    private lateinit var vault: Vault
    private lateinit var keyStore: KeystoreKeyStore
    private val recovery = DemoRecoveryProvider()

    /** Set once the SDK demo screen has initialized it. Null until then, and after destroy. */
    private var sdk: ShareRingVaultSdk? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val (createdVault, createdKeyStore) = Envelock.createVault(
            context = this,
            providerId = "envelock-demo",
            // Swap for BackendMaterialProvider to see the real pattern; see DemoProviders.kt
            // for why a local pepper is not a second factor.
            material = LocalDemoMaterialProvider(this),
            recovery = recovery,
            // UniFFI generates a plain interface rather than a `fun interface`, so this is an
            // object expression rather than a lambda.
            events = object : SecurityEventSink {
                override fun onEvent(event: uniffi.envelock.FfiSecurityEvent) {
                    android.util.Log.i("envelock", event.toString())
                }
            },
        )
        vault = createdVault
        keyStore = createdKeyStore

        setContent { DemoApp(vault, keyStore, recovery) { sdk = it } }
    }

    override fun onStop() {
        super.onStop()
        // Spec 11.3: zeroize on background. This happens inside the Rust core - dropping a
        // Kotlin reference gives no guarantee the key bytes ever leave memory, because an
        // immutable ByteArray may already have been copied by the GC.
        vault.lock()
        sdk?.lock()
    }
}

/**
 * Two demos, one app.
 *
 * **Vault directly** is [DemoScreen]: envelock as a standalone library, driven by the app
 * itself. **Inside an SDK** is [SdkDemoScreen], where the same vault is baked into a product
 * SDK ([ShareRingVaultSdk]) that exposes four calls and hides the vault entirely. envelock
 * depends on neither arrangement; both are just ways to consume it.
 */
@Composable
private fun DemoApp(
    vault: Vault,
    keyStore: KeystoreKeyStore,
    recovery: DemoRecoveryProvider,
    onSdk: (ShareRingVaultSdk?) -> Unit,
) {
    var sdkMode by remember { mutableStateOf(false) }

    Column {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(onClick = { sdkMode = false }) { Text("Vault directly") }
            Button(onClick = { sdkMode = true }) { Text("Inside an SDK") }
        }
        if (sdkMode) SdkDemoScreen(onSdk) else DemoScreen(vault, keyStore, recovery)
    }
}

@Composable
private fun DemoScreen(
    vault: Vault,
    keyStore: KeystoreKeyStore,
    recovery: DemoRecoveryProvider,
) {
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<VaultState?>(null) }
    var log by remember { mutableStateOf(listOf<String>()) }
    val demoKey = remember { ByteArray(32) { (it * 7 + 3).toByte() } }

    fun append(line: String) {
        log = (listOf(line) + log).take(40)
    }

    /// Every vault call runs off the main thread: unlock blocks on a biometric prompt.
    fun act(label: String, body: suspend () -> String) = scope.launch {
        try {
            val result = withContext(Dispatchers.IO) { body() }
            append("[ok] $label - $result")
        } catch (e: FfiVaultException.Cancelled) {
            // Normal behaviour, and explicitly not a failed attempt (spec 7.4).
            append("- $label - cancelled by user (not counted)")
        } catch (e: FfiVaultException) {
            append("[x] $label - ${e::class.simpleName}: ${e.message}")
        }
        state = withContext(Dispatchers.IO) { vault.state() }
    }

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("envelock", style = MaterialTheme.typography.headlineMedium)
            Text(
                "state: " + when (val s = state) {
                    null -> "..."
                    is FfiVaultState.LockedOut -> "LockedOut until ${s.untilMs}"
                    else -> s::class.simpleName ?: "?"
                },
                style = MaterialTheme.typography.bodyLarge,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { act("state") { vault.state()::class.simpleName ?: "?" } }) {
                    Text("Refresh")
                }
                Button(onClick = {
                    act("security info") {
                        val i = vault.securityInfo()
                        "${i.hardwareBacking} (hardware=${i.hardwareBacking.isHardwareBacked}) " +
                            "keyId=${i.keyId}"
                    }
                }) { Text("Info") }
            }

            Spacer(Modifier.height(4.dp))
            Text("Lifecycle", style = MaterialTheme.typography.titleMedium)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    act("enroll") {
                        vault.enroll(highEntropyFactor(demoKey))
                        "vault created, one prompt for enclave consent"
                    }
                }) { Text("Enroll") }

                Button(onClick = {
                    act("unlock") {
                        vault.unlock()
                        "one biometric prompt, cached material, no network"
                    }
                }) { Text("Unlock") }

                Button(onClick = {
                    act("lock") {
                        vault.lock()
                        // No iOS-style `invalidateContext()` here: Android's Keystore keys are
                        // configured to require authentication per use, so there is no cached
                        // authentication to drop.
                        "DEK zeroized in Rust"
                    }
                }) { Text("Lock") }
            }

            Spacer(Modifier.height(4.dp))
            Text("Records", style = MaterialTheme.typography.titleMedium)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    act("put") {
                        vault.put("card:1", "4111 1111 1111 1111".toByteArray())
                        "wrote card:1"
                    }
                }) { Text("Write") }

                Button(onClick = {
                    act("get") {
                        vault.get("card:1")?.let { String(it) } ?: "no such record"
                    }
                }) { Text("Read") }

                Button(onClick = { act("list") { vault.list("").toString() } }) { Text("List") }
            }

            Spacer(Modifier.height(4.dp))
            Text("Recovery", style = MaterialTheme.typography.titleMedium)

            Button(onClick = {
                act("simulate new device") {
                    // Deleting the enclave key is exactly what restoring a backup onto new
                    // hardware looks like from envelock's side: the envelope survives, the
                    // device-bound key does not.
                    vault.lock()
                    val removed = deleteDemoKeystoreEntries()
                    "deleted $removed enclave key(s); expect NeedsRecovery"
                }
            }) { Text("Simulate new device") }

            Button(onClick = {
                act("recover") {
                    vault.unlockWithRecovery()
                    "recovered (${recovery.lastReason}); primary path rewrapped, " +
                        "so the next unlock is biometric-only"
                }
            }) { Text("Recover") }

            Spacer(Modifier.height(4.dp))
            Text("Danger", style = MaterialTheme.typography.titleMedium)

            Button(onClick = {
                act("destroy") {
                    vault.destroyVault()
                    "enclave key, envelope, cache and records deleted - irreversible"
                }
            }) { Text("Destroy") }

            Spacer(Modifier.height(8.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    if (log.isEmpty()) {
                        Text("Tap Enroll to begin.", style = MaterialTheme.typography.bodySmall)
                    }
                    log.forEach {
                        Text(it, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
