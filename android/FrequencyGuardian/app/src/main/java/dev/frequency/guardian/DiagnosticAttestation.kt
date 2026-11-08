package dev.frequency.guardian

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import org.json.JSONArray
import org.json.JSONObject

/** Attested enrollment candidate. Operational signing requires an independent authority grant. */
internal class DiagnosticAttestation(private val context: Context) {
    private val alias = "frequency-guardian-attestation-candidate-v2"
    private val store get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun generate(challengeHex: String) {
        require(challengeHex.matches(Regex("[0-9a-fA-F]{64}"))) { "Supply exactly 32 random bytes as 64 hex characters from the independent verifier" }
        val challenge = challengeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        // Only this disposable diagnostic alias is replaced; the existing device key is untouched.
        check(!context.getSharedPreferences("offline-trust", Context.MODE_PRIVATE).contains("grant")) { "Existing enrollment must be revoked before candidate replacement" }
        store.deleteEntry(alias)
        try { generateKey(challenge, true) }
        catch (_: StrongBoxUnavailableException) { generateKey(challenge, false) }
    }

    private fun generateKey(challenge: ByteArray, strong: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setUnlockedDeviceRequired(true)
            .setAttestationChallenge(challenge)
            .setIsStrongBoxBacked(strong).build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(spec); generateKeyPair()
        }
    }

    fun publicKey(): java.security.PublicKey = store.getCertificate(alias)?.publicKey
        ?: error("Generate a diagnostic attestation candidate first")

    fun signer(): java.security.Signature {
        val key = store.getKey(alias, null) ?: error("No candidate key")
        val info = java.security.KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, android.security.keystore.KeyInfo::class.java)
        val hardware = if (android.os.Build.VERSION.SDK_INT >= 31)
            info.securityLevel in listOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProperties.SECURITY_LEVEL_STRONGBOX)
            else info.isInsideSecureHardware
        check(hardware && !info.isUserAuthenticationRequired) { "Hardware tap-approval key required" }
        return java.security.Signature.getInstance("SHA256withECDSA").apply { initSign(key as java.security.PrivateKey) }
    }

    fun certificateStatus(): DiagnosticResult {
        val chain = store.getCertificateChain(alias)
            ?: return DiagnosticResult(DiagnosticStatus.PENDING, "No candidate. Attestation requires a fresh external verifier challenge")
        return try {
            export() // Apply the same chain count and byte bounds as the public export.
            chain.forEach { (it as java.security.cert.X509Certificate).checkValidity() }
            check((chain.first() as java.security.cert.X509Certificate)
                .getExtensionValue("1.3.6.1.4.1.11129.2.1.17") != null) { "Android attestation extension missing" }
            DiagnosticResult(DiagnosticStatus.PENDING, "${chain.size} public certificates within local validity dates; NOT verified. External challenge, pinned-root, revocation and application identity require independent verification")
        } catch (e: Exception) {
            DiagnosticResult(DiagnosticStatus.FAIL, e.message ?: "Invalid candidate certificate chain")
        }
    }

    fun export(): String {
        val chain = store.getCertificateChain(alias) ?: error("Generate a diagnostic candidate first")
        require(chain.size in 2..8) { "Missing or oversized attestation chain" }
        var total = 0
        val certs = JSONArray()
        chain.forEach {
            val der = it.encoded
            require(der.size in 1..16384) { "Certificate too large" }
            total += der.size
            require(total <= 49152) { "Chain too large" }
            certs.put(der.b64())
        }
        val result = JSONObject().put("schema", "frequency-guardian-attestation/v2")
            .put("purpose", "diagnostic-only").put("production_eligible", false)
            .put("attestation_verified", false).put("certificates_der_b64", certs).toString(2)
        require(result.toByteArray(Charsets.UTF_8).size <= 70000) { "Export too large" }
        return result
    }
}
