package dev.frequency.guardian

import java.security.PublicKey
import java.security.Signature

internal enum class DiagnosticStatus { PASS, FAIL, PENDING }
internal data class DiagnosticResult(val status: DiagnosticStatus, val detail: String)

/** Public observations only. No key material or production authorization can enter this report. */
internal class DiagnosticsReport(val version: String, val created: Long = System.currentTimeMillis() / 1000) {
    val results = linkedMapOf<String, DiagnosticResult>().apply {
        names.forEach { put(it, DiagnosticResult(DiagnosticStatus.PENDING, "Not run")) }
    }
    fun set(name: String, status: DiagnosticStatus, detail: String) {
        require(name in names)
        results[name] = DiagnosticResult(status, detail)
    }
    fun json(): String = """{"schema":"frequency-guardian-diagnostics/v3","version":${quote(version)},"created_unix":$created,"production_eligible":false,"private_keys_exported":false,"external_attestation_challenge_required":true,"checks":{${results.entries.joinToString(",") { (name, result) -> "${quote(name)}:{\"status\":${quote(result.status.name.lowercase())},\"detail\":${quote(result.detail)}}" }}}}"""
    fun summary() = results.entries.joinToString("\n\n") { (name, result) -> "$name: ${result.status.name.lowercase()}\n${result.detail}" }
    companion object {
        val names = listOf("hardware", "ecdsa", "tampering", "nonce", "expiry", "identity_continuity", "strongbox", "attestation_certificate_status", "recovery_readiness", "update")
        private fun quote(value: String): String = "\"" + value.map { c -> when(c) {
            '"' -> "\\\""; '\\' -> "\\\\"; else -> if (c.code < 32) "\\u%04x".format(c.code) else c.toString()
        } }.joinToString("") + "\""
    }
}
internal object DiagnosticChecks {
    fun local(report: DiagnosticsReport) {
        val a = LocalFixture.create()
        val b = LocalFixture.create()
        check(a.nonce.size == 32 && !a.nonce.contentEquals(b.nonce))
        a.consume(a.issued)
        check(runCatching { a.consume(a.issued) }.isFailure)
        report.set("nonce", DiagnosticStatus.PASS, "Independent 32-byte nonces; consumed fixture refuses replay")
        check(runCatching { b.validate(b.issued - 1) }.isFailure)
        check(runCatching { b.validate(b.expires) }.isFailure)
        b.validate(b.issued)
        report.set("expiry", DiagnosticStatus.PASS, "Refuses before issuance and at expiry; 120-second local fixture")
    }
    fun signed(report: DiagnosticsReport, key: PublicKey, bytes: ByteArray, signature: ByteArray) {
        fun verifies(body: ByteArray) = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key); update(body); verify(signature)
        }
        check(verifies(bytes))
        report.set("ecdsa", DiagnosticStatus.PASS, "Authenticated device signature verified locally with SHA256withECDSA")
        check(!verifies(bytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }))
        report.set("tampering", DiagnosticStatus.PASS, "Modified action digest rejected by signature verification")
    }
}
