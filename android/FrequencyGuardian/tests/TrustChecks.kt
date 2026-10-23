package dev.frequency.guardian

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

fun main() {
    var checks = 0
    fun refuses(action: () -> Unit) { check(runCatching(action).isFailure); checks++ }
    val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val authority = TrustProtocol.key(keys.public.encoded)
    fun envelope(s: TrustProtocol.Statement, suffix: ByteArray = byteArrayOf()): String {
        val bytes = TrustProtocol.payload(s) + suffix
        val sig = Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(bytes); sign() }
        return bytes.b64() + "." + sig.b64()
    }
    val grant = TrustProtocol.Statement(1, "a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64), 1000, 2000, "")
    val valid = envelope(grant)
    check(TrustProtocol.verify(valid, authority, 1000) == grant)
    refuses { TrustProtocol.verify(valid, other.public, 1000) }
    refuses { TrustProtocol.verify(valid, authority, 999) }
    refuses { TrustProtocol.verify(valid, authority, 2000) }
    refuses { TrustProtocol.verify(valid + ".extra", authority, 1000) }
    refuses { TrustProtocol.verify("A".repeat(16001), authority, 1000) }
    refuses { TrustProtocol.verify(envelope(grant, byteArrayOf(0)), authority, 1000) }
    refuses { TrustProtocol.verify(envelope(grant.copy(expires = 87401)), authority, 1000) }
    refuses { TrustProtocol.bound(grant, "x", grant.signer) }
    refuses { TrustProtocol.bound(grant, grant.device, "x") }
    refuses { TrustProtocol.bound(grant, grant.device, grant.signer, "x") }
    refuses { envelope(grant.copy(nonce = "0".repeat(64))) }
    refuses { envelope(grant.copy(kind = 4)) }
    refuses { envelope(grant.copy(action = "hidden")) }
    val request = grant.copy(kind = 2, expires = 1120, action = "Execute reviewed action: transfer 5 units")
    check(TrustProtocol.verify(envelope(request), authority, 1119) == request)
    refuses { TrustProtocol.verify(envelope(request), authority, 1120) }
    refuses { TrustProtocol.verify(envelope(request.copy(expires = 1121)), authority, 1000) }
    refuses { envelope(request.copy(action = "")) }
    refuses { envelope(request.copy(action = "a\nb")) }
    refuses { envelope(request.copy(action = "a\u202eb")) }
    refuses { envelope(request.copy(action = "a".repeat(4097))) }
    val approved = TrustProtocol.receipt(request, true)
    val denied = TrustProtocol.receipt(request, false)
    check(!approved.contentEquals(denied))
    val sig = Signature.getInstance("SHA256withECDSA").run { initSign(other.private); update(approved); sign() }
    check(Signature.getInstance("SHA256withECDSA").run { initVerify(other.public); update(approved); verify(sig) })
    check(!Signature.getInstance("SHA256withECDSA").run { initVerify(other.public); update(denied); verify(sig) })
    check(!Signature.getInstance("SHA256withECDSA").run { initVerify(other.public); update(TrustProtocol.payload(request)); verify(sig) })
    check(TrustProtocol.verify(envelope(request.copy(kind = 3, action = "")), authority, 1000).kind == 3)
    println("PASS: offline trust authority signature, canonical encoding, device/APK/enrollment binding, expiry, bounded input, visible action text, approve/deny domain separation; $checks negative cases")
}
