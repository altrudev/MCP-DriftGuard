package dev.frequency.guardian

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.*
import org.json.JSONObject
import java.security.Signature
import java.time.Instant

class MainActivity : Activity() {
    private lateinit var column: LinearLayout
    private lateinit var identity: DeviceIdentity
    private lateinit var online: OnlineApproval
    private var onlineStatus: TextView? = null
    private lateinit var offline: OfflineApproval
    private var diagnosticDialog: AlertDialog? = null
    private var diagnostics: DiagnosticsReport? = null
    private var offlineStatus: TextView? = null
    private var diagnosticView: TextView? = null
    private var pendingExport: ByteArray? = null
    private fun refreshDiagnostics() { diagnosticView?.text = diagnostics?.summary() ?: "Run diagnostics to collect evidence." }
    private fun runAllDiagnostics() {
        val report = DiagnosticsReport(BuildConfig.VERSION_NAME)
        diagnostics = report
        fun observe(name: String, action: () -> Unit) {
            try { action() } catch (e: Exception) { report.set(name, DiagnosticStatus.FAIL, e.message ?: "Check failed") }
        }
        observe("nonce") { DiagnosticChecks.local(report) }
        report.set("recovery_readiness", DiagnosticStatus.PENDING, "Recovery ceremony, independent offline identity and quorum are not implemented; not recovery ready")
        report.set("update", DiagnosticStatus.PENDING, "In-place update requires same package and APK certificate; physical-device upgrade acceptance is still required")
        report.set("attestation_certificate_status", DiagnosticStatus.PENDING, "External verifier challenge required to generate attestation; chain, pinned root, challenge and revocation require independent verification")
        observe("attestation_certificate_status") {
            val status = DiagnosticAttestation(this).certificateStatus()
            report.set("attestation_certificate_status", status.status, status.detail)
        }
        observe("hardware") {
            identity.provision()
            report.set("hardware", if (identity.hardware()) DiagnosticStatus.PASS else DiagnosticStatus.FAIL, identity.status())
            report.set("strongbox", identity.strongBoxStatus(), identity.status())
            val fingerprint = identity.fingerprint()
            val baseline = settings.getString("diagnostic-identity-baseline", null)
            report.set("identity_continuity", when { baseline == null -> DiagnosticStatus.PENDING; baseline == fingerprint -> DiagnosticStatus.PENDING; else -> DiagnosticStatus.FAIL },
                if (baseline == null) "First observation; local baseline recorded: $fingerprint" else "Local SPKI baseline unchanged: $fingerprint. Independent continuity, authorized upgrade and remote identity binding remain UNVERIFIED")
            if (baseline == null) check(settings.edit().putString("diagnostic-identity-baseline", fingerprint).commit())
        }
        refreshDiagnostics()
        try { report.set("ecdsa", DiagnosticStatus.PENDING, "Awaiting explicit Approve; no automatic signing"); refreshDiagnostics(); review() }
        catch (e: Exception) { report.set("ecdsa", DiagnosticStatus.FAIL, e.message ?: "Signing unavailable"); refreshDiagnostics() }
    }
    private val settings get() = getSharedPreferences("nonsecret-settings", MODE_PRIVATE)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        applyTheme()
        identity = DeviceIdentity(this)
        offline = OfflineApproval(this, ::saveJson)
        online = OnlineApproval(this, offline) {
            onlineStatus?.text = it
            offlineStatus?.text = offline.status()
        }
        render()
        if (intent.action != Intent.ACTION_MAIN && intent.action != null) {
            toast("External approval requests are unsupported and refused")
        }
    }
    private fun applyTheme() {
        val mode = when (settings.getString("theme", "system")) { "dark" -> android.app.UiModeManager.MODE_NIGHT_YES; "light" -> android.app.UiModeManager.MODE_NIGHT_NO; else -> android.app.UiModeManager.MODE_NIGHT_AUTO }
        // Override configuration locally; do not modify system theme.
        val night = when (mode) { android.app.UiModeManager.MODE_NIGHT_YES -> Configuration.UI_MODE_NIGHT_YES; android.app.UiModeManager.MODE_NIGHT_NO -> Configuration.UI_MODE_NIGHT_NO; else -> resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK }
        if ((resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) != night) {
            val config = Configuration(resources.configuration)
            config.uiMode = (config.uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or night
            resources.updateConfiguration(config, resources.displayMetrics)
        }
        setTheme(if (night == Configuration.UI_MODE_NIGHT_YES) android.R.style.Theme_Material_NoActionBar else android.R.style.Theme_Material_Light_NoActionBar)
    }
    private fun label(text: String, size: Float = 16f) {
        column.addView(TextView(this).apply { this.text = text; textSize = size; setPadding(0, 12, 0, 12); setTextIsSelectable(true) })
    }
    private fun button(title: String, action: () -> Unit) {
        column.addView(Button(this).apply { text = title; isAllCaps = false; filterTouchesWhenObscured = true; setOnClickListener { guarded(action) } })
    }
    private fun render() {
        column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(28, 30, 28, 40) }
        setContentView(ScrollView(this).apply {
            addView(column)
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
            requestApplyInsets()
        })
        label("Frequency Guardian", 28f)
        label("v${BuildConfig.VERSION_NAME} • Online approval", 18f)
        offlineStatus = TextView(this).apply { text = offline.status(); textSize = 16f; setPadding(0, 12, 0, 12) }
        column.addView(offlineStatus)
        onlineStatus = TextView(this).apply { text = online.initialStatus(); textSize = 18f }
        column.addView(onlineStatus)
        button("Pair HTTPS approval server") { online.pair() }
        button("Fetch signed enrollment") { online.enroll() }
        button("Check requests / delivery status") { offline.stop(); online.check() }
        button("Send saved decision") { online.deliver() }
        button("Discard unconfirmed saved delivery") { online.discard() }
        label("Setup: pin independent verifier, generate and export attestation, have operator verify it, then pair server and fetch signed enrollment. Review Who / What / Target / Expiry and tap Approve or Deny. No extra password or biometric prompt. Keep app visible for 15-second polling.")
        button("Pin independent verifier") { offline.pin() }
        button("Save candidate enrollment identity") { offline.exportIdentity() }
        button("Import signed enrollment / request / revocation") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) }, 3)
        }
        button("Revoke this enrollment locally") {
            AlertDialog.Builder(this).setTitle("Revoke this device key?")
                .setMessage("This permanently blocks this candidate locally. Also revoke it at the independent verifier. Recovery requires a new independently verified candidate.")
                .setNegativeButton("Cancel", null).setPositiveButton("Revoke") { _, _ -> guarded { offline.revoke(); recreate() } }.show()
        }
        button("Run All Diagnostics") { runAllDiagnostics() }
        if (identity.needsMigration()) button("Migrate legacy diagnostic identity to tap approval") {
            AlertDialog.Builder(this).setTitle("Use tap-to-approve?")
                .setMessage("This generates a NEW hardware-backed key without per-action biometrics. The original key is preserved; any trusted enrollment must be independently reverified. Anyone using this unlocked phone could approve.")
                .setNegativeButton("Deny", null)
                .setPositiveButton("Approve") { _, _ -> guarded { identity.migrateWithConsent(); toast("Simple approval identity created; new enrollment required"); recreate() } }.show()
        }
        diagnosticView = TextView(this).apply { textSize = 15f; setTextIsSelectable(true) }
        column.addView(diagnosticView)
        refreshDiagnostics()
        button("Save diagnostics JSON") {
            val report = diagnostics ?: error("Run All Diagnostics first")
            saveJson("frequency-guardian-diagnostics.json", report.json())
        }
        guarded {
            identity.provision()
            label(identity.status())
            label("Public key SHA-256 (SPKI)\n${identity.fingerprint()}")
            button("Copy diagnostic pairing payload") { copy(identity.pairing()) }
            button("Save pairing JSON") { saveJson("frequency-guardian-pairing.json", identity.pairing()) }
            button("Review local signing diagnostic") { review() }
        }
        label("Operational candidate: independent attestation and signed enrollment required before decisions.")
        button("Generate attestation candidate") {
            val input = EditText(this).apply {
                hint = "Independent verifier challenge: 64 hex characters"
                filters = arrayOf(android.text.InputFilter.LengthFilter(64))
                inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            }
            AlertDialog.Builder(this).setTitle("Generate fresh enrollment candidate?")
                .setMessage("Paste a fresh 32-byte challenge issued by the independent verifier. An existing enrollment must be revoked before replacing its candidate. No trust is granted by generation.")
                .setView(input).setNegativeButton("Cancel", null)
                .setPositiveButton("Generate") { _, _ -> guarded {
                    DiagnosticAttestation(this).generate(input.text.toString())
                    toast("Candidate generated; independent enrollment required")
                } }.show()
        }
        button("Sign candidate binding JSON") {
            val input = EditText(this).apply {
                hint = "Verifier challenge (64 hex characters)"
                filters = arrayOf(android.text.InputFilter.LengthFilter(64))
            }
            AlertDialog.Builder(this).setTitle("Bind existing key to attested candidate")
                .setMessage("Use the SAME independent challenge as the candidate. Tap Approve to sign the association; no enrollment is granted.")
                .setView(input).setNegativeButton("Cancel", null)
                .setPositiveButton("Approve") { _, _ -> guarded { bindCandidate(input.text.toString()) } }.show()
        }
        button("Save attestation JSON") {
            AlertDialog.Builder(this).setTitle("Save public attestation evidence?")
                .setMessage("Certificates may contain identifying device and application metadata. Save only to a trusted location. This does not enroll or trust the device.")
                .setNegativeButton("Cancel", null).setPositiveButton("Save JSON") { _, _ -> guarded {
                    saveJson("frequency-guardian-attestation.json", DiagnosticAttestation(this).export())
                } }.show()
        }
        button("Theme: ${settings.getString("theme", "system")}") {
            AlertDialog.Builder(this).setTitle("Appearance").setItems(arrayOf("System", "Light", "Dark")) { _, which ->
                settings.edit().putString("theme", arrayOf("system", "light", "dark")[which]).apply(); recreate()
            }.show()
        }
        button("Export nonsecret settings") { exportSettings() }
        button("Import nonsecret settings") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "application/json"; addCategory(Intent.CATEGORY_OPENABLE) }, 1)
        }
        button("About, security & recovery") { about() }
    }
    private fun bindCandidate(challengeHex: String) {
        require(challengeHex.matches(Regex("[0-9a-fA-F]{64}"))) { "Expected 64 hexadecimal characters" }
        val candidate = DiagnosticAttestation(this).publicKey().encoded
        val old = identity.publicKey().encoded
        check(!candidate.contentEquals(old)) { "Distinct candidate identity required" }
        val challenge = challengeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val msg = "frequency-guardian/attested-candidate-binding/v1\u0000".toByteArray(Charsets.US_ASCII) +
            challenge + digest.digest(old) + digest.digest(candidate)
        val signer = identity.signer()
        signer.update(msg)
        val signature = signer.sign()
        check(Signature.getInstance("SHA256withECDSA").run {
            initVerify(identity.publicKey()); update(msg); verify(signature)
        }) { "Local binding signature failed" }
        val payload = JSONObject().put("schema", "frequency-guardian-candidate-binding/v1")
            .put("old_public_key_spki_b64", old.b64())
            .put("candidate_public_key_spki_b64", candidate.b64())
            .put("challenge_hex", challengeHex.lowercase())
            .put("signature_der_b64", signature.b64())
            .put("production_eligible", false).toString(2)
        saveJson("frequency-guardian-candidate-binding.json", payload)
    }
    private fun review() {
        val fixture = LocalFixture.create()
        diagnosticDialog?.dismiss()
        diagnosticDialog = AlertDialog.Builder(this).setTitle("Local diagnostic • no action authorized")
            .setMessage("Source: generated in this app, not a paired broker.\n\n${String(fixture.action, Charsets.UTF_8)}\n\nNonce: ${fixture.nonce.hex()}\nIssued: ${Instant.ofEpochSecond(fixture.issued)}\nExpires: ${Instant.ofEpochSecond(fixture.expires)}\nAction SHA-256: ${fixture.digest.hex()}\n\nApprove signs only this diagnostic domain without an extra authentication prompt.")
            .setNegativeButton("Deny") { _, _ -> diagnostics?.set("ecdsa", DiagnosticStatus.PENDING, "Diagnostic denied; no signature"); refreshDiagnostics() }.setPositiveButton("Approve") { _, _ -> guarded { approveFixture(fixture) } }.show()
    }
    private fun approveFixture(fixture: LocalFixture) {
        fixture.validate(System.currentTimeMillis()/1000)
        val bytes = fixture.consume(System.currentTimeMillis()/1000)
        val signer = identity.signer()
        signer.update(bytes)
        val signed = signer.sign()
        check(Signature.getInstance("SHA256withECDSA").run { initVerify(identity.publicKey()); update(bytes); verify(signed) }) { "Signature verification failed" }
        diagnostics?.let { DiagnosticChecks.signed(it, identity.publicKey(), bytes, signed); refreshDiagnostics() }
        toast("Approved local diagnostic only")
    }
    override fun onDestroy() { online.close(); super.onDestroy() }
    override fun onStart() { super.onStart(); online.start() }
    override fun onStop() {
        online.stop()
        offline.stop()
        diagnosticDialog?.dismiss(); diagnosticDialog = null
        super.onStop()
    }
    private fun saveJson(filename: String, payload: String) {
        check(pendingExport == null) { "Finish the previous export first" }
        val bytes = payload.toByteArray(Charsets.UTF_8)
        require(bytes.size <= 70000) { "JSON export exceeds safety limit" }
        JSONObject(payload) // refuse malformed JSON before creating a document
        pendingExport = bytes
        try {
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/json"
                putExtra(Intent.EXTRA_TITLE, filename)
            }, 2)
        } catch (e: Exception) { pendingExport = null; throw e }
    }
    private fun exportSettings() {
        saveJson("frequency-guardian-settings.json", JSONObject()
            .put("schema", "frequency-guardian-settings/v1")
            .put("theme", settings.getString("theme", "system")).toString(2))
    }
    @Deprecated("Platform activity result used to avoid external dependencies")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 2) {
            val bytes = pendingExport
            pendingExport = null
            if (resultCode != RESULT_OK) return
            guarded {
                check(bytes != null) { "No export pending" }
                val uri = data?.data ?: error("No save destination")
                contentResolver.openOutputStream(uri, "wt")?.use { output ->
                    output.write(bytes)
                    output.flush()
                } ?: error("Cannot save JSON to selected location")
                toast("JSON saved to selected document")
            }
            return
        }
        if (requestCode == 3) {
            if (resultCode != RESULT_OK) return
            guarded {
                val uri = data?.data ?: error("No trust document")
                val bytes = contentResolver.openInputStream(uri)?.use { input ->
                    val buffer = java.io.ByteArrayOutputStream()
                    val chunk = ByteArray(1024)
                    while (buffer.size() <= 16000) {
                        val n = input.read(chunk, 0, minOf(chunk.size, 16001 - buffer.size()))
                        if (n < 0) break
                        buffer.write(chunk, 0, n)
                    }
                    buffer.toByteArray()
                } ?: error("Cannot read trust document")
                require(bytes.size <= 16000) { "Trust document too large" }
                offline.importDocument(bytes.toString(Charsets.US_ASCII))
                offlineStatus?.text = offline.status()
            }
            return
        }
        if (requestCode != 1 || resultCode != RESULT_OK) return
        guarded {
            val uri = data?.data ?: error("No settings document")
            val bytes = contentResolver.openInputStream(uri)?.use { input ->
                val buffer = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(512)
                while (buffer.size() < 4097) {
                    val count = input.read(chunk, 0, minOf(chunk.size, 4097 - buffer.size()))
                    if (count < 0) break
                    buffer.write(chunk, 0, count)
                }
                buffer.toByteArray() } ?: error("Cannot read document")
            require(bytes.size <= 4096) { "Settings too large" }
            val raw = bytes.toString(Charsets.UTF_8)
            // A deliberately tiny exact grammar rejects duplicate keys, trailing data and extra fields.
            val match = Regex("""\s*\{\s*"schema"\s*:\s*"frequency-guardian-settings/v1"\s*,\s*"theme"\s*:\s*"(system|light|dark)"\s*}\s*""").matchEntire(raw)
                ?: error("Unsupported settings; only exported v1 theme settings are accepted")
            val theme = match.groupValues[1]
            AlertDialog.Builder(this).setTitle("Import appearance setting?").setMessage("Theme: $theme\nNo identity, pairing, trust, or recovery state will be imported.")
                .setNegativeButton("Cancel", null).setPositiveButton("Import") { _, _ -> settings.edit().putString("theme", theme).apply(); recreate() }.show()
        }
    }
    private fun about() {
        AlertDialog.Builder(this).setTitle("About & security • v${BuildConfig.VERSION_NAME}")
            .setMessage("Native Kotlin • Android 11+\n\nKey: nonexportable Android Keystore P-256, explicit tap approval required in the interface; no per-action biometric or password. StrongBox preferred; TEE fallback reported; software keys cannot sign. HTTPS foreground polling; no telemetry, backups, or private-key migration. Pairing payload is an unverified diagnostic enrollment candidate, not authorization.\n\nLost phone: recovery must be provisioned BEFORE loss with an independent offline recovery identity and quorum policy. Quorum must revoke the lost key and activate a newly attested device. Offline enrollment requires a separately pinned independent verifier. Local revocation permits a fresh candidate; no automatic recovery or authority replacement is allowed. Do not uninstall or clear storage expecting identity recovery.\n\nGlossary: SPKI = encoded public key; nonce = one-use random challenge; digest = SHA-256 action commitment; attestation = hardware evidence requiring independent verification; quorum = required independent approvals.\n\nIP boundary: repository Apache-2.0/NOTICE applies. No proprietary Frequency/DDC/DSR implementation or branding license is implied. See COMMERCIAL.md and the mobile contract.")
            .setPositiveButton("Close", null).show()
    }
    private fun shareText(text: String) { startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, text) }, "Share public diagnostic data")) }
    private fun copy(text: String) { getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Public pairing payload", text)); toast("Public pairing payload copied") }
    private fun toast(message: String) { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
    private fun guarded(action: () -> Unit) { try { action() } catch (e: Exception) { labelError(e.message ?: e.javaClass.simpleName) } }
    private fun labelError(message: String) { toast(message); if (::column.isInitialized) label("Unavailable / refused: $message") }
}
