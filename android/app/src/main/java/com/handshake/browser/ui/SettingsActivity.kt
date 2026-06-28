package com.handshake.browser.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Paint
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.handshake.browser.BuildConfig
import com.handshake.browser.net.NativeBridge
import org.json.JSONObject

class SettingsActivity : ComponentActivity() {
    private lateinit var homepageStatus: TextView
    private lateinit var hnsModeStatus: TextView
    private lateinit var resolverCacheStatus: TextView
    private lateinit var historyStatus: TextView
    private lateinit var downloadStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        homepageStatus = statusRow("Current homepage", BrowserPreferences.homepage(this))
        hnsModeStatus = statusRow("Current mode", hnsModeText())
        resolverCacheStatus = statusRow("Resolver cache", "Ready")
        historyStatus = statusRow("Browsing history", historySummary())
        downloadStatus = statusRow("Downloads", downloadSummary())

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 32, 32, 32)
            applySystemBarPadding()
            addView(heading("Settings"))

            addView(sectionHeading("Homepage / startup"))
            addView(homepageStatus)
            addView(actionButton("Edit homepage") {
                showEditHomepageDialog()
            })
            currentUrlFromIntent()?.let { currentUrl ->
                addView(actionButton("Use current page as homepage") {
                    useCurrentPageAsHomepage(currentUrl)
                })
            }
            addView(actionButton("Reset homepage") {
                confirmResetHomepage()
            })

            addView(sectionHeading("HNS resolution"))
            addView(strictHnsModeOption())
            addView(bodyText("Strict mode never uses the third-party HNS DoH compatibility fallback. Compatibility mode may use it when a current local HNS proof is unavailable or direct delegated resolution fails."))
            addView(hnsModeStatus)
            addView(actionButton("View diagnostics") {
                startActivity(Intent(this@SettingsActivity, DiagnosticsActivity::class.java))
            })
            addView(actionButton("Clear resolver cache") {
                confirmClearResolverCache()
            })
            addView(resolverCacheStatus)

            addView(sectionHeading("Browser privacy / website data"))
            addView(actionButton("Cookie options") {
                startActivity(Intent(this@SettingsActivity, CookieSettingsActivity::class.java))
            })
            addView(actionButton("View history") {
                startActivity(Intent(this@SettingsActivity, HistoryActivity::class.java))
            })
            addView(actionButton("Clear browsing history") {
                confirmClearHistory()
            })
            addView(historyStatus)

            addView(sectionHeading("Downloads"))
            addView(actionButton("View downloads") {
                startActivity(Intent(this@SettingsActivity, DownloadsActivity::class.java))
            })
            addView(actionButton("Clear app download records") {
                confirmClearDownloadRecords()
            })
            addView(downloadStatus)
            addView(bodyText("Download files are managed by Android. This app only stores the small list of downloads it queued."))

            addView(sectionHeading("Diagnostics and tools"))
            addView(actionButton("Make my HNS domain work") {
                startActivity(Intent(this@SettingsActivity, HnsDomainWizardActivity::class.java))
            })
            addView(actionButton("Resolver trace") {
                startActivity(Intent(this@SettingsActivity, HnsResolverTraceActivity::class.java))
            })
            addView(actionButton("HNS proof details") {
                startActivity(Intent(this@SettingsActivity, HnsProofDetailsActivity::class.java))
            })
            addView(actionButton("TLSA / DANE inspector") {
                startActivity(Intent(this@SettingsActivity, HnsTlsaInspectorActivity::class.java))
            })

            addView(sectionHeading("About / legal / support"))
            addView(statusRow("Build", buildLabel()))
            addView(actionButton("License and user agreement") {
                startActivity(Intent(this@SettingsActivity, LegalActivity::class.java))
            })
            addView(linkRow(
                label = "Source code",
                value = BrowserAppInfo.SOURCE_CODE_URL,
                uri = BrowserAppInfo.SOURCE_CODE_URL,
                copyLabel = "source code URL",
                copyText = BrowserAppInfo.SOURCE_CODE_URL,
            ))
            addView(bodyText("Donations are optional and unlock no features."))
            addView(linkRow(
                label = "Donate HNS",
                value = BrowserAppInfo.HNS_DONATION_ADDRESS,
                uri = BrowserAppInfo.HNS_DONATION_URI,
                copyLabel = "HNS donation address",
                copyText = BrowserAppInfo.HNS_DONATION_ADDRESS,
            ))
        }

        setContentView(
            ScrollView(this).apply {
                addView(root)
            },
        )
    }

    override fun onResume() {
        super.onResume()
        if (::homepageStatus.isInitialized) {
            refreshHomepageStatus()
            refreshHistoryStatus()
            refreshDownloadStatus()
        }
    }

    private fun heading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 24f
            setPadding(0, 0, 0, 14)
        }

    private fun sectionHeading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 20f
            setPadding(0, 24, 0, 8)
        }

    private fun bodyText(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 15f
            setTextIsSelectable(true)
            setPadding(0, 4, 0, 12)
        }

    private fun actionButton(text: String, action: () -> Unit): Button =
        Button(this).apply {
            this.text = text
            setAllCaps(false)
            setOnClickListener { action() }
        }

    private fun statusRow(label: String, value: String): TextView =
        TextView(this).apply {
            text = "$label: $value"
            textSize = 16f
            setTextIsSelectable(true)
            setPadding(0, 6, 0, 10)
        }

    private fun strictHnsModeOption(): CheckBox =
        CheckBox(this).apply {
            text = "Strict HNS mode: never use third-party HNS DoH fallback"
            textSize = 16f
            setPadding(0, 0, 0, 14)
            isChecked = HnsResolutionPreferences.strictHnsMode(this@SettingsActivity)
            setOnCheckedChangeListener { _, checked ->
                HnsResolutionPreferences.setStrictHnsMode(this@SettingsActivity, checked)
                hnsModeStatus.text = "Current mode: ${hnsModeText()}"
            }
        }

    private fun linkRow(label: String, value: String, uri: String, copyLabel: String, copyText: String): TextView =
        statusRow(label, value).apply {
            paintFlags = paintFlags or Paint.UNDERLINE_TEXT_FLAG
            setTextColor(0xff1565c0.toInt())
            setTextIsSelectable(false)
            isClickable = true
            setOnClickListener {
                openLink(Uri.parse(uri), copyLabel, copyText)
            }
        }

    private fun openLink(uri: Uri, copyLabel: String, copyText: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, uri))
        } catch (_: ActivityNotFoundException) {
            getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText(copyLabel, copyText))
            Toast.makeText(this, "Copied $copyLabel", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showEditHomepageDialog() {
        val input = EditText(this).apply {
            setText(BrowserPreferences.homepage(this@SettingsActivity))
            setSingleLine(true)
            setSelection(0, text.length)
            imeOptions = EditorInfo.IME_ACTION_DONE
        }

        val dialog = AlertDialog.Builder(this)
            .setTitle("Edit homepage")
            .setMessage("Enter an http:// or https:// URL, or an HNS name such as example/ or www.example/.")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val saved = BrowserPreferences.setHomepage(this, input.text.toString())
                if (saved == null) {
                    input.error = "Enter an HTTP(S) URL or HNS name"
                    return@setOnClickListener
                }
                refreshHomepageStatus()
                Toast.makeText(this, "Homepage saved", Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun useCurrentPageAsHomepage(currentUrl: String) {
        val saved = BrowserPreferences.setHomepage(this, currentUrl)
        if (saved == null) {
            Toast.makeText(this, "Current page is not a supported homepage URL", Toast.LENGTH_SHORT).show()
            return
        }
        refreshHomepageStatus()
        Toast.makeText(this, "Homepage saved", Toast.LENGTH_SHORT).show()
    }

    private fun confirmResetHomepage() {
        AlertDialog.Builder(this)
            .setTitle("Reset homepage?")
            .setMessage("This restores the built-in HNS browser start page.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Reset") { _, _ ->
                BrowserPreferences.resetHomepage(this)
                refreshHomepageStatus()
                Toast.makeText(this, "Homepage reset", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun confirmClearResolverCache() {
        AlertDialog.Builder(this)
            .setTitle("Clear resolver cache?")
            .setMessage("The app will keep synced headers and peers, but cached HNS resource values will be removed.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                clearResolverCache()
            }
            .show()
    }

    private fun clearResolverCache() {
        val result = NativeBridge.clearResolverCache(filesDir.absolutePath)
        val status = runCatching { JSONObject(result).optString("status") }.getOrDefault("")
        val message = if (status == "cleared") {
            "Resolver cache cleared"
        } else {
            "Resolver cache did not report a successful clear"
        }
        resolverCacheStatus.text = "$message: $result"
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun confirmClearHistory() {
        val count = BrowserHistoryStore.entries(this).size
        if (count == 0) {
            Toast.makeText(this, "History is already empty", Toast.LENGTH_SHORT).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Clear history?")
            .setMessage("This removes the app's local browsing history.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                val cleared = BrowserHistoryStore.clear(this)
                refreshHistoryStatus()
                Toast.makeText(this, "Cleared $cleared history item(s)", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun confirmClearDownloadRecords() {
        val count = BrowserDownloadStore.records(this).size
        if (count == 0) {
            Toast.makeText(this, "Download records are already empty", Toast.LENGTH_SHORT).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Clear download records?")
            .setMessage("This clears this browser's download list. It does not delete downloaded files.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                val cleared = BrowserDownloadStore.clear(this)
                refreshDownloadStatus()
                Toast.makeText(this, "Cleared $cleared download record(s)", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun refreshHomepageStatus() {
        homepageStatus.text = "Current homepage: ${BrowserPreferences.homepage(this)}"
    }

    private fun refreshHistoryStatus() {
        historyStatus.text = "Browsing history: ${historySummary()}"
    }

    private fun refreshDownloadStatus() {
        downloadStatus.text = "Downloads: ${downloadSummary()}"
    }

    private fun hnsModeText(): String =
        if (HnsResolutionPreferences.strictHnsMode(this)) {
            "Strict. Delegated resolution failures fail closed."
        } else {
            "Compatibility. HNS DoH fallback may be used after proof availability or delegated resolution failures."
        }

    private fun historySummary(): String {
        val count = BrowserHistoryStore.entries(this).size
        return "$count saved page${if (count == 1) "" else "s"}"
    }

    private fun downloadSummary(): String {
        val count = BrowserDownloadStore.records(this).size
        return "$count app-queued record${if (count == 1) "" else "s"}"
    }

    private fun currentUrlFromIntent(): String? =
        intent.getStringExtra(EXTRA_CURRENT_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) "debug demo" else "release"
        return "$channel ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
    }

    companion object {
        const val EXTRA_CURRENT_URL = "com.handshake.browser.CURRENT_URL"
    }
}
