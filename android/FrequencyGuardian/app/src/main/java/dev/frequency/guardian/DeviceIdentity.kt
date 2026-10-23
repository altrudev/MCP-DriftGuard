package dev.frequency.guardian

import android.content.Context
import android.app.KeyguardManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.os.Build
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.json.JSONObject

internal class DeviceIdentity(private val context: Context) {
    private val alias = "frequency-guardian-diagnostic-p256-v1"
    private val store get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val prefs get() = context.getSharedPreferences("identity-status", Context.MODE_PRIVATE)
    fun provision() {
        check(context.getSystemService(KeyguardManager::class.java).isDeviceSecure) { "Set a device PIN/password first" }
        if (store.containsAlias(alias)) return
        try {
            generate(true)
            prefs.edit().putString("fallback", "None: StrongBox requested and key generated").commit()
        } catch (e: StrongBoxUnavailableException) {
            generate(false)
            prefs.edit().putString("fallback", "StrongBox unavailable; standard Android Keystore fallback used").commit()
        }
    }
    private fun generate(strong: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .setIsStrongBoxBacked(strong).build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec); generateKeyPair() }
    }
    private fun info(): KeyInfo {
        val key = store.getKey(alias, null)
        return KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
    }
    fun hardware(): Boolean = if (Build.VERSION.SDK_INT >= 31) info().securityLevel in listOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProperties.SECURITY_LEVEL_STRONGBOX) else info().isInsideSecureHardware
    fun status(): String {
        val i = info()
        val level = if (Build.VERSION.SDK_INT >= 31) when (i.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "Trusted Execution Environment (TEE)"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software — signing disabled"
            else -> "Unknown — signing disabled"
        } else if (i.isInsideSecureHardware) "Secure hardware (API 30 cannot distinguish TEE/StrongBox)" else "Software — signing disabled"
        return "Security level: $level\n${prefs.getString("fallback", "Creation fallback history unavailable")}\nLocal KeyInfo only; no remote attestation verification."
    }
    fun publicKey() = store.getCertificate(alias).publicKey
    fun fingerprint() = MessageDigest.getInstance("SHA-256").digest(publicKey().encoded).hex()
    fun pairing(): String = JSONObject().put("schema", "frequency-guardian-pairing/v1")
        .put("purpose", "diagnostic-only").put("algorithm", "ES256")
        .put("public_key_spki_b64", publicKey().encoded.b64()).put("fingerprint_sha256", fingerprint())
        .put("attestation_verified", false).put("production_eligible", false).toString(2)
    fun signer(): Signature {
        check(hardware()) { "Hardware-backed key required; signing refused" }
        return Signature.getInstance("SHA256withECDSA").apply { initSign(store.getKey(alias, null) as java.security.PrivateKey) }
    }
}
