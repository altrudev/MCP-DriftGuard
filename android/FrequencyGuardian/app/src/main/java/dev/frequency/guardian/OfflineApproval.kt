package dev.frequency.guardian

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageManager
import android.widget.EditText
import org.json.JSONObject
import java.security.Signature
import java.util.Base64

/** Persistent local enforcement; exports and UI diagnostics never establish trust. */
internal class OfflineApproval(private val activity: Activity, private val export: (String, String) -> Unit) {
    private val prefs = activity.getSharedPreferences("offline-trust", Context.MODE_PRIVATE)
    private val candidate = DiagnosticAttestation(activity)
    private var dialog: AlertDialog? = null
    private var pending: String? = null
    fun reviewing(): Boolean = pending != null
    private fun now(): Long {
        val now = System.currentTimeMillis() / 1000
        check(now >= prefs.getLong("clock", 0)) { "Clock rollback; signing blocked" }
        check(prefs.edit().putLong("clock", now).commit()) { "Cannot persist clock" }
        return now
    }
    private fun authority() = TrustProtocol.key(Base64.getDecoder().decode(prefs.getString("authority", null) ?: error("Pin independent verifier first")))
    private fun device() = TrustProtocol.hash(candidate.publicKey().encoded)
    @Suppress("DEPRECATION")
    private fun signer(): String {
        val info = activity.packageManager.getPackageInfo(activity.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signatures = info.signingInfo?.apkContentsSigners ?: error("APK signer unavailable")
        require(signatures.size == 1) { "Ambiguous APK signer" }
        return TrustProtocol.hash(signatures.single().toByteArray())
    }
    private fun revoked(device: String) = prefs.getStringSet("revoked", emptySet())!!.contains(device)
    fun enrolled(): Boolean = runCatching { grant(); true }.getOrDefault(false)
    fun status(): String = "Offline approval: " + when {
        !prefs.contains("authority") -> "verifier not pinned; blocked"
        !prefs.contains("grant") -> "not enrolled; blocked"
        else -> runCatching { grant(); "signed enrollment valid (fresh authority request still required)" }.getOrElse { "blocked: ${it.message}" }
    }
    fun pin() {
        check(!prefs.contains("authority")) { "Verifier already pinned. In-place authority replacement is disabled" }
        val input = EditText(activity).apply { hint = "P-256 SPKI base64 then independently verified SHA-256 hex, separated by space" }
        AlertDialog.Builder(activity).setTitle("Pin independent verifier")
            .setMessage("Obtain the key and fingerprint through separate authenticated channels. A key or fingerprint supplied with the phone's exports is not independent verification. This pin cannot be replaced here.")
            .setView(input).setNegativeButton("Cancel", null).setPositiveButton("Pin") { _, _ -> safe {
                val fields = input.text.toString().trim().split(Regex("\\s+"))
                require(fields.size == 2)
                val key = TrustProtocol.key(Base64.getDecoder().decode(fields[0]))
                require(TrustProtocol.hash(key.encoded) == fields[1]) { "Independent fingerprint mismatch" }
                check(prefs.edit().putString("authority", key.encoded.b64()).commit())
                message("Verifier pinned. Import an independently issued enrollment grant next.")
            } }.show()
    }
    fun exportIdentity() {
        export("frequency-guardian-enrollment-identity.json", JSONObject()
            .put("schema", "frequency-guardian-offline-identity/v1")
            .put("candidate_spki_b64", candidate.publicKey().encoded.b64())
            .put("candidate_sha256", device()).put("package", activity.packageName)
            .put("apk_signer_sha256", signer()).put("trusted", false).toString(2))
    }
    private fun grant(): TrustProtocol.Statement {
        val g = TrustProtocol.verify(prefs.getString("grant", null) ?: error("No independently signed enrollment"), authority(), now())
        require(g.kind == 1)
        TrustProtocol.bound(g, device(), signer())
        check(!revoked(g.device)) { "Device permanently revoked" }
        return g
    }
    fun importDocument(text: String, delivery: ((String, String) -> Unit)? = null) {
        check(pending == null) { "Finish or dismiss the pending request" }
        val s = TrustProtocol.verify(text, authority(), now())
        TrustProtocol.bound(s, device(), signer())
        if (s.kind == 3) { revoke(); return }
        check(!revoked(s.device)) { "Revoked key cannot be enrolled again; generate a new independently verified candidate" }
        if (s.kind == 1) {
            check(prefs.getStringSet("revoked", emptySet())!!.size < 256) { "Revocation ledger full; new enrollment blocked" }
            check(!prefs.contains("grant")) { "Existing enrollment cannot be replaced; revoke first" }
            check(prefs.edit().putString("grant", text).commit())
            message("Independent authority enrollment signature verified. Requests still require fresh authority signatures.")
            return
        }
        val g = grant()
        TrustProtocol.bound(s, g.device, g.signer, g.enrollment)
        val used = prefs.getStringSet("used", emptySet())!!
        check(!used.contains(s.nonce) && used.size < 8192) { "Replay or local replay ledger full; signing blocked" }
        val start = android.os.SystemClock.elapsedRealtime()
        pending = text
        dialog = AlertDialog.Builder(activity).setTitle("Review authority request")
            .setMessage("${s.action.replace(" | ", "\n\n")}\n\nEnrollment: ${s.enrollment}\nNonce: ${s.nonce}\nExpires: ${java.time.Instant.ofEpochSecond(s.expires)}\nAction SHA-256: ${TrustProtocol.hash(s.action.toByteArray(Charsets.UTF_8))}")
            .setNegativeButton("Deny") { _, _ -> safe { decide(text, false, start, delivery) } }
            .setPositiveButton("Approve") { _, _ -> safe { decide(text, true, start, delivery) } }
            .setOnDismissListener { pending = null; dialog = null }.show()
        dialog?.getButton(AlertDialog.BUTTON_POSITIVE)?.filterTouchesWhenObscured = true
        dialog?.getButton(AlertDialog.BUTTON_NEGATIVE)?.filterTouchesWhenObscured = true
    }
    private fun decide(text: String, approved: Boolean, start: Long, delivery: ((String, String) -> Unit)?) {
        check(pending == text && !activity.isFinishing && !activity.isDestroyed)
        check(android.os.SystemClock.elapsedRealtime() - start < 120000) { "Review expired" }
        val s = TrustProtocol.verify(text, authority(), now())
        val g = grant()
        TrustProtocol.bound(s, g.device, g.signer, g.enrollment)
        val used = prefs.getStringSet("used", emptySet())!!.toMutableSet()
        check(used.size < 8192 && used.add(s.nonce)) { "Request already consumed or ledger full" }
        // Persist before signing/export. Failure burns the request; never retry an uncertain decision.
        check(prefs.edit().putStringSet("used", used).commit()) { "Cannot consume request" }
        pending = null
        val bytes = TrustProtocol.receipt(s, approved)
        val signature = candidate.signer().run { update(bytes); sign() }
        check(Signature.getInstance("SHA256withECDSA").run { initVerify(candidate.publicKey()); update(bytes); verify(signature) })
        val receipt = JSONObject().put("schema", "frequency-guardian-offline-decision/v1")
            .put("decision", if (approved) "approve" else "deny").put("signed_bytes_b64", bytes.b64())
            .put("signature_der_b64", signature.b64()).put("device_spki_b64", candidate.publicKey().encoded.b64()).toString(2)
        if (delivery != null) delivery(receipt, s.nonce) else export("frequency-guardian-decision.json", receipt)
    }
    fun revoke() {
        val blocked = prefs.getStringSet("revoked", emptySet())!!.toMutableSet()
        blocked.add(device())
        check(blocked.size <= 256) { "Revocation ledger full; replacement disabled" }
        check(prefs.edit().putStringSet("revoked", blocked).remove("grant").commit())
        stop()
        message("Device key locally revoked. The independent verifier must also revoke it before recovery. Generate a new candidate and repeat independent enrollment; no trust is transferred.")
    }
    fun stop() { pending = null; dialog?.dismiss(); dialog = null }
    private fun message(text: String) { AlertDialog.Builder(activity).setMessage(text).setPositiveButton("Close", null).show() }
    private fun safe(action: () -> Unit) { try { action() } catch (e: Exception) { message("Refused: ${e.message}") } }
}
