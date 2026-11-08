package dev.frequency.guardian

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.EditText
import android.widget.LinearLayout
import org.json.JSONObject
import javax.net.ssl.HttpsURLConnection
import java.net.URL
import java.util.concurrent.Executors

/** Foreground-only polling. Platform TLS validation is never bypassed. */
internal class OnlineApproval(private val activity: Activity, private val offline: OfflineApproval,
    private val status: (String) -> Unit) {
    private val prefs = activity.getSharedPreferences("online-pairing", Context.MODE_PRIVATE)
    private val handler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private var active = false
    private var busy = false
    private var generation = 0
    private val tick = object : Runnable {
        override fun run() {
            if (!active) return
            if (!busy && !offline.reviewing() && !prefs.contains("outbox") && prefs.contains("endpoint") && offline.enrolled()) poll()
            handler.postDelayed(this, 15000)
        }
    }
    fun initialStatus(): String = prefs.getString("confirmed", null) ?: "Pair a verified server to receive requests. Polling runs only while visible."
    fun close() { worker.shutdownNow() }
    fun discard() {
        check(!busy) { "Wait for the active connection" }
        AlertDialog.Builder(activity).setTitle("Discard unconfirmed delivery?")
            .setMessage("Check delivery first. Discarding cannot undo a server acceptance. This request remains consumed locally. Ask the operator to inspect the durable receipt and issue a fresh request if needed.")
            .setNegativeButton("Cancel", null).setPositiveButton("Discard saved delivery") { _, _ ->
                // A delivery can start after this dialog opens. Never erase its recovery state.
                if (busy) {
                    status("Wait for the active connection, then check delivery before discarding.")
                    return@setPositiveButton
                }
                if (prefs.edit().remove("outbox").remove("nonce").commit()) status("Saved delivery discarded; server result may still exist. Check with operator.")
            }.show()
    }
    fun start() { active = true; handler.removeCallbacks(tick); handler.post(tick) }
    fun stop() { active = false; generation++; handler.removeCallbacks(tick) }
    fun pair() {
        check(!busy && !offline.reviewing() && !prefs.contains("outbox")) { "Finish/check active review or saved delivery before changing transport pairing" }
        val layout = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        val endpoint = EditText(activity).apply {
            hint = "Independently verified HTTPS origin"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            setText(prefs.getString("endpoint", ""))
        }
        val token = EditText(activity).apply {
            hint = "Private operator-issued pairing token"; inputType = 129
            importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO
            setSingleLine(true)
        }
        layout.addView(endpoint); layout.addView(token)
        val dialog = AlertDialog.Builder(activity).setTitle("Pair approval server")
            .setMessage("First pin the independent authority and generate/export your attested candidate below. The operator must verify it before issuing this token. Confirm this server address through an authenticated channel. This explicit pairing can replace transport settings; the independently pinned authority and device identity remain required. Pairing does not pin any authority. Tokens are stored privately on this phone; anyone using this unlocked phone can approve.")
            .setView(layout).setNegativeButton("Cancel", null).setPositiveButton("Pair this server", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply {
                filterTouchesWhenObscured = true
                setOnClickListener {
                runCatching {
                    val origin = OnlineProtocol.endpoint(endpoint.text.toString().trim())
                    val secret = OnlineProtocol.token(token.text.toString().trim())
                    check(!busy && !offline.reviewing() && !prefs.contains("outbox")) { "Finish active review or delivery first" }
                    check(prefs.edit().putString("endpoint", origin).putString("token", secret).commit())
                    token.text.clear()
                    dialog.dismiss()
                    if (offline.enrolled()) status("Server paired explicitly; existing signed enrollment retained") else enroll()
                }.onFailure {
                    endpoint.error = "Check the HTTPS origin and private pairing token"
                    status("Pairing refused: ${it.message}")
                }
                }
            }
        }
        dialog.show()
    }
    private fun api(route: String, body: JSONObject): JSONObject {
        val origin = OnlineProtocol.endpoint(prefs.getString("endpoint", null) ?: error("Pair server first"))
        val connection = URL(origin + route).openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 8000; connection.readTimeout = 8000
            connection.requestMethod = "POST"; connection.doOutput = true
            connection.setRequestProperty("Authorization", "Bearer " + OnlineProtocol.token(prefs.getString("token", "")!!))
            connection.setRequestProperty("Content-Type", "application/json")
            val bytes = body.toString().toByteArray(Charsets.UTF_8)
            require(bytes.size <= 70000); connection.setFixedLengthStreamingMode(bytes.size)
            connection.outputStream.use { it.write(bytes) }
            check(connection.responseCode == 200) { "Server refused; no acceptance confirmed" }
            val response = connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                while (output.size() < 70001) {
                    val count = input.read(chunk, 0, minOf(chunk.size, 70001 - output.size()))
                    if (count < 0) break
                    output.write(chunk, 0, count)
                }
                output.toByteArray()
            }
            require(response.size <= 70000)
            return JSONObject(response.toString(Charsets.UTF_8))
        } finally { connection.disconnect() }
    }
    private fun run(route: String, body: JSONObject, done: (JSONObject) -> Unit) {
        if (busy) return
        busy = true
        val epoch = generation
        worker.execute {
            val result = runCatching { api(route, body) }
            handler.post {
                busy = false
                if (active && epoch == generation) result.onSuccess { data ->
                    runCatching { done(data) }.onFailure { status("Refused: ${it.message}") }
                }.onFailure { status("Unconfirmed: ${it.message}. Use Check delivery after a decision.") }
            }
        }
    }
    fun enroll() = run("/v1/enroll", JSONObject()) {
        offline.importDocument(it.getString("enrollment"))
        status("Enrollment verified locally. Waiting for requests from ${prefs.getString("endpoint", "")}")
    }
    fun poll() = run("/v1/pending", JSONObject()) {
        if (it.isNull("request")) { status("No pending requests. Polls every 15 seconds while visible."); return@run }
        offline.importDocument(it.getString("request")) { receipt, nonce ->
            check(prefs.edit().putString("outbox", receipt).putString("nonce", nonce).commit()) { "Cannot persist delivery; acceptance unknown" }
            status("Signed decision saved; awaiting server confirmation")
            deliver()
        }
        status("Review the signed request. Backgrounding cancels review; tap Check requests to reopen.")
    }
    fun check() {
        check(!offline.reviewing()) { "Finish or dismiss the active review first" }
        if (prefs.contains("outbox")) {
            run("/v1/status", JSONObject().put("nonce", prefs.getString("nonce", ""))) { confirm(it) }
        } else poll()
    }
    fun deliver() {
        val receipt = prefs.getString("outbox", null) ?: error("No saved decision")
        run("/v1/decision", JSONObject().put("receipt", JSONObject(receipt))) { confirm(it) }
    }
    private fun confirm(result: JSONObject) {
        val receipt = JSONObject(prefs.getString("outbox", null) ?: error("No saved decision"))
        require(result.getString("nonce") == prefs.getString("nonce", "") &&
            result.getString("device") == TrustProtocol.hash(java.util.Base64.getDecoder().decode(receipt.getString("device_spki_b64"))) &&
            result.getString("verified_decision") == receipt.getString("decision") && !result.getBoolean("executed"))
        val message = "Server confirmed ${result.getString("verified_decision").uppercase()}. Receipt durably recorded. No action executed."
        check(prefs.edit().remove("outbox").remove("nonce").putString("confirmed", message).commit())
        status(message)
    }
}
