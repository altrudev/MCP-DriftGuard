package dev.frequency.guardian

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Offline authority statements. The authority is provisioned independently, never from an export. */
internal object TrustProtocol {
    const val DOMAIN = "frequency-guardian/offline-trust/v1"
    data class Statement(val kind: Int, val device: String, val signer: String, val enrollment: String,
        val nonce: String, val issued: Long, val expires: Long, val action: String)
    fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    fun key(encoded: ByteArray): PublicKey {
        require(encoded.size in 64..512)
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
        require(key is ECPublicKey && key.params.order == java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)) { "P-256 authority required" }
        return key
    }
    fun payload(s: Statement): ByteArray {
        require(s.kind in 1..3)
        listOf(s.device, s.signer, s.enrollment, s.nonce).forEach { require(it.matches(Regex("[0-9a-f]{64}"))) }
        require(s.nonce != "0".repeat(64))
        require(s.action.length <= 4096 && s.action.none { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }) { "Unsafe action text" }
        require((s.kind == 2 && s.action.isNotBlank()) || (s.kind != 2 && s.action.isEmpty()))
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { out ->
            out.writeUTF(DOMAIN); out.writeByte(s.kind)
            listOf(s.device, s.signer, s.enrollment, s.nonce).forEach { out.writeUTF(it) }
            out.writeLong(s.issued); out.writeLong(s.expires); out.writeUTF(s.action)
        }
        return output.toByteArray()
    }
    fun verify(envelope: String, authority: PublicKey, now: Long): Statement {
        require(envelope.length <= 16000)
        val parts = envelope.trim().split('.')
        require(parts.size == 2)
        val decoder = Base64.getDecoder()
        val body = decoder.decode(parts[0]); val signature = decoder.decode(parts[1])
        require(body.size <= 12000 && signature.size in 8..80)
        check(Signature.getInstance("SHA256withECDSA").run { initVerify(authority); update(body); verify(signature) }) { "Authority signature invalid" }
        val input = DataInputStream(ByteArrayInputStream(body))
        require(input.readUTF() == DOMAIN) { "Wrong trust domain" }
        val s = Statement(input.readUnsignedByte(), input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF(), input.readLong(), input.readLong(), input.readUTF())
        require(input.available() == 0 && payload(s).contentEquals(body)) { "Noncanonical statement" }
        require(s.issued > 0 && s.issued <= now && s.expires > now && s.expires > s.issued)
        require(s.expires - s.issued <= if (s.kind == 1) 86400L else 120L) { "Statement lifetime exceeded" }
        return s
    }
    fun bound(s: Statement, device: String, signer: String, enrollment: String? = null) {
        require(s.device == device && s.signer == signer) { "Device or installed APK signer mismatch" }
        if (enrollment != null) require(s.enrollment == enrollment) { "Enrollment mismatch" }
    }
    fun receipt(s: Statement, approved: Boolean): ByteArray =
        "frequency-guardian/offline-decision/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(if (approved) 1 else 0) + payload(s)
}
