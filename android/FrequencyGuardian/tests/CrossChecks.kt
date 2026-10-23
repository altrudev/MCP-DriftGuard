package dev.frequency.guardian

import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec

/** Python authority -> Kotlin app verification -> Python receipt verification. */
fun main() {
    val root = File(System.getenv("FG_TEST_OUT"), "cross")
    val authority = TrustProtocol.key(File(root, "authority.der").readBytes())
    val statement = TrustProtocol.verify(File(root, "request.fg").readText(), authority, 1000)
    check(statement.action == "Cross-language reviewed action")
    val device = TrustProtocol.key(File(root, "device.der").readBytes())
    TrustProtocol.bound(statement, TrustProtocol.hash(device.encoded), "b".repeat(64), "c".repeat(64))
    val privateKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(File(root, "device.pk8").readBytes()))
    for (approved in listOf(true, false)) {
        val body = TrustProtocol.receipt(statement, approved)
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(privateKey); update(body); sign() }
        File(root, "${approved}.body").writeBytes(body)
        File(root, "${approved}.sig").writeBytes(signature)
    }
    println("PASS: independent Python authority request verified by native Kotlin protocol; both decisions signed")
}
