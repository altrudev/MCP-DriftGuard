package dev.frequency.guardian

import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec

private fun refuses(block: () -> Unit) {
    check(runCatching(block).isFailure) { "Expected refusal" }
}
fun main() {
    val f = LocalFixture.create()
    val domain = "frequency-guardian/diagnostic-approval/v1\u0000".toByteArray(Charsets.US_ASCII)
    val expectedAction = "Diagnostic only: verify local signing; authorize no operation.".toByteArray()
    val expected = domain + byteArrayOf(1) + f.nonce +
        ByteBuffer.allocate(16).putLong(f.issued).putLong(f.expires).array() +
        MessageDigest.getInstance("SHA-256").digest(expectedAction)
    check(f.bytes().contentEquals(expected))
    check(f.expires == f.issued + 120)
    check(f.action.contentEquals(expectedAction))
    check(!f.nonce.contentEquals(LocalFixture.create().nonce))
    val immutableNonce = f.nonce
    immutableNonce.fill(0)
    check(f.bytes().contentEquals(expected))
    f.action.fill(0)
    f.validate(f.issued)
    refuses { f.validate(f.issued - 1) }
    refuses { f.validate(f.expires) }
    refuses { f.validate(Long.MAX_VALUE) }
    val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val bytes = f.consume(f.issued)
    val sig = Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(bytes); sign() }
    fun verifiesBody(body: ByteArray): Boolean = Signature.getInstance("SHA256withECDSA").run { initVerify(key.public); update(body); this.verify(sig) }
    check(verifiesBody(bytes))
    check(!verifiesBody(bytes.copyOf().also { it[domain.size] = 2 }))
    check(!verifiesBody(bytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }))
    check(!verifiesBody("frequency-guardian/approval/v1\u0000".toByteArray() + bytes.copyOfRange(domain.size, bytes.size)))
    refuses { f.consume(f.issued) }
    refuses { f.validate(f.issued) }
    val report = DiagnosticsReport("0.4.0", 123)
    check(report.results.size == 10)
    check(report.results.values.all { it.status == DiagnosticStatus.PENDING })
    DiagnosticChecks.local(report)
    check(report.results["nonce"]?.status == DiagnosticStatus.PASS)
    check(report.results["expiry"]?.status == DiagnosticStatus.PASS)
    DiagnosticChecks.signed(report, key.public, bytes, sig)
    check(report.results["ecdsa"]?.status == DiagnosticStatus.PASS)
    check(report.results["tampering"]?.status == DiagnosticStatus.PASS)
    refuses { DiagnosticChecks.signed(DiagnosticsReport("test"), key.public, bytes + 1, sig) }
    refuses { report.set("unknown", DiagnosticStatus.PASS, "invalid") }
    report.set("update", DiagnosticStatus.FAIL, "quote\" newline\n slash\\")
    val json = report.json()
    check(json.contains("\"production_eligible\":false"))
    check(json.contains("\"private_keys_exported\":false"))
    check(json.contains("\"external_attestation_challenge_required\":true"))
    check(json.contains("quote\\\" newline\\u000a slash\\\\"))
    check(json.contains("\"status\":\"fail\""))
    check(report.results["attestation_certificate_status"]?.status == DiagnosticStatus.PENDING)
    java.io.File(System.getenv("FG_TEST_OUT"), "report.json").writeText(json)
    println("PASS: diagnostics schema, ten statuses, safe defaults, JSON escaping, real signature and negative verification")
    println("PASS: exact v1 encoding, nonce independence, immutable fields, time bounds, single consumption, ECDSA verification, tamper and cross-domain rejection")
}
