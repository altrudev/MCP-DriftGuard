package dev.frequency.guardian

import android.app.Activity
import android.app.AlertDialog
import android.hardware.biometrics.BiometricPrompt
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.*
import org.json.JSONObject
import java.security.Signature
import java.time.Instant

class MainActivity : Activity() {
    private lateinit var column: LinearLayout
    private lateinit var identity: DeviceIdentity
    private var cancellation: CancellationSignal? = null
    private var activeFixture: LocalFixture? = null
    private var diagnostics: DiagnosticsReport? = null
    private var diagnosticView: TextView? = null
    private fun refreshDiagnostics() { diagnosticView?.text = diagnostics?.summary() ?: "Run diagnostics to collect evidence." }
    private fun runAllDiagnostics() {
        check(activeFixture == null) { "Authentication already pending" }
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
            report.set("identity_continuity", when { baseline == null -> DiagnosticStatus.PENDING; baseline == fingerprint -> DiagnosticStatus.PASS; else -> DiagnosticStatus.FAIL },
                if (baseline == null) "First observation; local baseline recorded: $fingerprint" else "Local baseline comparison; current SPKI SHA-256: $fingerprint. Does not establish remote enrollment or reinstall continuity")
            if (baseline == null) check(settings.edit().putString("diagnostic-identity-baseline", fingerprint).commit())
        }
        refreshDiagnostics()
        try { authenticate(LocalFixture.create(), report) }
        catch (e: Exception) { report.set("ecdsa", DiagnosticStatus.FAIL, e.message ?: "Signing unavailable"); refreshDiagnostics() }
    }
    private val settings get() = getSharedPreferences("nonsecret-settings", MODE_PRIVATE)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        applyTheme()
        identity = DeviceIdentity(this)
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
        column.addView(Button(this).apply { text = title; isAllCaps = false; setOnClickListener { guarded(action) } })
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
        label("v${BuildConfig.VERSION_NAME} • Offline diagnostic", 18f)
        label("Production approvals disabled. No broker connection, remote request import, or operational authorization.")
        button("Run All Diagnostics") { runAllDiagnostics() }
        diagnosticView = TextView(this).apply { textSize = 15f; setTextIsSelectable(true) }
        column.addView(diagnosticView)
        refreshDiagnostics()
        button("Export diagnostics JSON") {
            val report = diagnostics ?: error("Run All Diagnostics first")
            java.io.File(cacheDir, "diagnostics.json").writeText(report.json())
            val uri = Uri.parse("content://$packageName.settings/diagnostics.json")
            startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                type = "application/json"; putExtra(Intent.EXTRA_STREAM, uri)
                clipData = ClipData.newRawUri("Diagnostic results", uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }, "Export diagnostic report (public observations only)"))
        }
        guarded {
            identity.provision()
            label(identity.status())
            label("Public key SHA-256 (SPKI)\n${identity.fingerprint()}")
            button("Copy diagnostic pairing payload") { copy(identity.pairing()) }
            button("Share diagnostic pairing payload") { shareText(identity.pairing()) }
            button("Review local signing diagnostic") { review() }
        }
        label("Attestation candidate: separate P-256 key; no trust or enrollment is enabled.")
        button("Generate diagnostic attestation candidate") {
            val input = EditText(this).apply {
                hint = "Independent verifier challenge: 64 hex characters"
                filters = arrayOf(android.text.InputFilter.LengthFilter(64))
                inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            }
            AlertDialog.Builder(this).setTitle("Replace diagnostic candidate only?")
                .setMessage("Paste a fresh externally generated random 32-byte challenge. Randomness cannot be verified here. The existing device signing key is preserved. No automatic trust.")
                .setView(input).setNegativeButton("Cancel", null)
                .setPositiveButton("Generate") { _, _ -> guarded {
                    DiagnosticAttestation(this).generate(input.text.toString())
                    toast("Diagnostic candidate generated; unverified and not enrolled")
                } }.show()
        }
        button("Export diagnostic certificate chain") {
            AlertDialog.Builder(this).setTitle("Share public attestation evidence?")
                .setMessage("Certificates can contain identifying device, application and hardware metadata. Share only with a trusted offline reviewer. Export contains public certificates only, no private key, credentials or settings. This does not enroll or trust the device.")
                .setNegativeButton("Cancel", null).setPositiveButton("Share diagnostic chain") { _, _ -> guarded {
                    shareText(DiagnosticAttestation(this).export())
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
    private fun review() {
        val fixture = LocalFixture.create()
        AlertDialog.Builder(this).setTitle("Local diagnostic • no action authorized")
            .setMessage("Source: generated in this app, not a paired broker.\n\n${String(fixture.action, Charsets.UTF_8)}\n\nNonce: ${fixture.nonce.hex()}\nIssued: ${Instant.ofEpochSecond(fixture.issued)}\nExpires: ${Instant.ofEpochSecond(fixture.expires)}\nAction SHA-256: ${fixture.digest.hex()}\n\nAuthentication signs only this diagnostic domain.")
            .setNegativeButton("Cancel", null).setPositiveButton("Authenticate & sign") { _, _ -> guarded { authenticate(fixture) } }.show()
    }
    private fun authenticate(fixture: LocalFixture, report: DiagnosticsReport? = null) {
        check(activeFixture == null) { "Authentication already pending" }
        fixture.validate(System.currentTimeMillis() / 1000)
        val signer = identity.signer()
        val signal = CancellationSignal()
        cancellation = signal
        activeFixture = fixture
        val prompt = BiometricPrompt.Builder(this).setTitle("Sign local diagnostic")
            .setSubtitle("No production operation will be approved")
            .setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG or android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL).build()
        prompt.authenticate(BiometricPrompt.CryptoObject(signer), signal, mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(code: Int, message: CharSequence) {
                activeFixture = null; cancellation = null
                report?.set("ecdsa", DiagnosticStatus.PENDING, "Authentication cancelled or unavailable: $message")
                refreshDiagnostics(); toast("Not signed: $message")
            }
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val pending = activeFixture
                activeFixture = null; cancellation = null
                if (pending !== fixture || isFinishing || isDestroyed) return
                try {
                    fixture.validate(System.currentTimeMillis() / 1000)
                    val authorized = result.cryptoObject?.signature ?: error("Missing authenticated signing operation")
                    check(authorized === signer) { "Unexpected signing operation" }
                    authorized.update(fixture.consume(System.currentTimeMillis() / 1000))
                    val signature = authorized.sign()
                    check(Signature.getInstance("SHA256withECDSA").run { initVerify(identity.publicKey()); update(fixture.bytes()); verify(signature) })
                    if (report != null) {
                        try { DiagnosticChecks.signed(report, identity.publicKey(), fixture.bytes(), signature) }
                        catch (e: Exception) { report.set("tampering", DiagnosticStatus.FAIL, e.message ?: "Verification failed") }
                        refreshDiagnostics()
                        return
                    }
                    val receipt = JSONObject().put("schema", "frequency-guardian-diagnostic-signature/v1")
                        .put("production_eligible", false).put("algorithm", "ES256-DER")
                        .put("signed_bytes_b64", fixture.bytes().b64()).put("signature_der_b64", signature.b64())
                        .put("fingerprint_sha256", identity.fingerprint()).toString(2)
                    AlertDialog.Builder(this@MainActivity).setTitle("Diagnostic signature verified locally")
                        .setMessage(receipt).setPositiveButton("Close", null).setNeutralButton("Share") { _, _ -> shareText(receipt) }.show()
                } catch (e: Exception) {
                    report?.set("ecdsa", DiagnosticStatus.FAIL, e.message ?: "Signing failed")
                    refreshDiagnostics()
                    labelError(e.message ?: "Signing failed")
                }
            }
        })
    }
    override fun onStop() {
        if (activeFixture != null) {
            diagnostics?.takeIf { it.results["ecdsa"]?.status == DiagnosticStatus.PENDING }
                ?.set("ecdsa", DiagnosticStatus.PENDING, "Interrupted; rerun and complete system authentication")
            refreshDiagnostics()
        }
        activeFixture = null; cancellation?.cancel(); cancellation = null; super.onStop()
    }
    private fun exportSettings() {
        val json = JSONObject().put("schema", "frequency-guardian-settings/v1").put("theme", settings.getString("theme", "system")).toString(2)
        java.io.File(cacheDir, "settings.json").writeText(json)
        val uri = Uri.parse("content://$packageName.settings/settings.json")
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
            type = "application/json"; putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newRawUri("Nonsecret settings", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }, "Export nonsecret settings"))
    }
    @Deprecated("Platform activity result used to avoid external dependencies")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
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
            .setMessage("Native Kotlin • Android 11+\n\nKey: nonexportable Android Keystore P-256, authentication required for every signature. StrongBox preferred; TEE fallback reported; software keys cannot sign. No Internet permission, telemetry, backups, or private-key migration. Pairing payload is an unverified diagnostic enrollment candidate, not authorization.\n\nLost phone: recovery must be provisioned BEFORE loss with an independent offline recovery identity and quorum policy. Quorum must revoke the lost key and activate a newly attested device. This app cannot perform recovery or production enrollment yet. Do not uninstall or clear storage expecting identity recovery.\n\nGlossary: SPKI = encoded public key; nonce = one-use random challenge; digest = SHA-256 action commitment; attestation = hardware evidence requiring independent verification; quorum = required independent approvals.\n\nIP boundary: repository Apache-2.0/NOTICE applies. No proprietary Frequency/DDC/DSR implementation or branding license is implied. See COMMERCIAL.md and the mobile contract.")
            .setPositiveButton("Close", null).show()
    }
    private fun shareText(text: String) { startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, text) }, "Share public diagnostic data")) }
    private fun copy(text: String) { getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Public pairing payload", text)); toast("Public pairing payload copied") }
    private fun toast(message: String) { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
    private fun guarded(action: () -> Unit) { try { action() } catch (e: Exception) { labelError(e.message ?: e.javaClass.simpleName) } }
    private fun labelError(message: String) { toast(message); if (::column.isInitialized) label("Unavailable / refused: $message") }
}
