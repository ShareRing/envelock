package network.sharering.envelock.demo

import android.content.Context
import java.security.SecureRandom
import javax.net.ssl.HttpsURLConnection
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import network.sharering.envelock.KeyMaterial
import network.sharering.envelock.KeyMaterialProvider
import network.sharering.envelock.RecoveryFactor
import network.sharering.envelock.RecoveryProvider
import network.sharering.envelock.highEntropyFactor
import org.json.JSONObject
import uniffi.envelock.FfiMaterialContext
import uniffi.envelock.FfiRecoveryReason
import uniffi.envelock.FfiVaultException

/**
 * A material provider that keeps the pepper on the device.
 *
 * ## Demo only - this is not a second factor
 *
 * A locally-stored pepper sits next to the envelope, so a rooted device yields both and the
 * material adds nothing the enclave key was not already contributing. The vault still has the
 * hardware key behind its OS gate, but you no longer get two independent factors. Point
 * [BackendMaterialProvider] at something like `examples/reference-backend` for that.
 *
 * What it does get right: the bytes are written once and read back forever. That is the
 * determinism contract, and the part integrators break.
 */
class LocalDemoMaterialProvider(context: Context) : KeyMaterialProvider {

    private val file = File(context.filesDir, "demo-pepper.bin")

    override fun getKeyMaterial(ctx: FfiMaterialContext): KeyMaterial {
        val material = if (file.exists()) {
            file.readBytes()
        } else {
            ByteArray(32).also {
                SecureRandom().nextBytes(it)
                file.writeBytes(it)
            }
        }

        return KeyMaterial(
            material = material,
            // A fixed keyId: rotation is a deliberate act, never a side effect of a call.
            keyId = "demo-v1",
            cacheable = true,
            cacheTtlMs = 30uL * 24uL * 60uL * 60uL * 1000uL,
        )
    }
}

/**
 * The shape a real provider takes (spec 9.1).
 *
 * Point it at `examples/reference-backend`. It carries a bearer token to *fetch* the material
 * and never derives anything from it - tokens rotate, and material derived from a rotating
 * value orphans every vault on the next rotation.
 */
class BackendMaterialProvider(
    private val endpoint: String,
    private val bearerToken: () -> String,
) : KeyMaterialProvider {

    override fun getKeyMaterial(ctx: FfiMaterialContext): KeyMaterial {
        val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Authorization", "Bearer ${bearerToken()}")
        }

        // A production build must refuse plain HTTP outright: the pepper is in the response.
        if (connection !is HttpsURLConnection && !endpoint.startsWith("http://10.0.2.2")) {
            connection.disconnect()
            throw FfiVaultException.Misconfigured("refusing to fetch key material over HTTP")
        }

        try {
            connection.outputStream.use {
                // The nonce lets the backend bind its response to this request. envelock does
                // not inspect it; nothing in the key hierarchy depends on it.
                val nonce = android.util.Base64.encodeToString(
                    ctx.nonce, android.util.Base64.NO_WRAP
                )
                it.write(JSONObject().put("nonce", nonce).toString().toByteArray())
            }

            // 401 is a real denial and counts toward lockout. Everything else is transient and
            // must not, or a backend outage marches a legitimate user into lockout (spec 7.4).
            when (connection.responseCode) {
                200 -> Unit
                401, 403 -> throw FfiVaultException.Denied()
                else -> throw FfiVaultException.Unavailable()
            }

            val body = JSONObject(connection.inputStream.bufferedReader().readText())
            return KeyMaterial(
                material = android.util.Base64.decode(
                    body.getString("material"), android.util.Base64.NO_WRAP
                ),
                keyId = body.getString("keyId"),
                cacheable = true,
                cacheTtlMs = 30uL * 24uL * 60uL * 60uL * 1000uL,
            )
        } catch (e: FfiVaultException) {
            throw e
        } catch (e: Exception) {
            // Any transport failure is retryable, never a denial.
            throw FfiVaultException.Unavailable()
        } finally {
            connection.disconnect()
        }
    }
}

/**
 * Supplies the recovery factor.
 *
 * A wallet would derive this from its BIP-39 seed with `envelock-bip85`, at a hardened path,
 * and would never let the seed phrase itself reach envelock. This demo uses a fixed key so the
 * recovery path can be exercised without a wallet.
 *
 * **The recovery factor is not the host app's PIN** (spec 0). envelock never compares it
 * against a stored value; it is KDF input and nothing else.
 */
class DemoRecoveryProvider : RecoveryProvider {

    /// A wallet would call `derive_recovery_key(seed, 0)` here instead.
    private val demoKey = ByteArray(32) { (it * 7 + 3).toByte() }

    var lastReason: FfiRecoveryReason? = null
        private set

    override fun getRecoveryFactor(reason: FfiRecoveryReason): RecoveryFactor {
        lastReason = reason
        return highEntropyFactor(demoKey)
    }
}
