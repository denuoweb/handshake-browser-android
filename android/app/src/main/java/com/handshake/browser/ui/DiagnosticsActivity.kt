package com.handshake.browser.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Paint
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.webkit.WebViewFeature
import com.handshake.browser.BuildConfig
import com.handshake.browser.net.HnsSyncForegroundService
import com.handshake.browser.net.NativeBridge
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class DiagnosticsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        HnsSyncForegroundService.start(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 32, 32, 32)
            applySystemBarPadding()
        }

        val syncStatus = row("Sync status", NativeBridge.syncStatus(filesDir.absolutePath))

        root.addView(row("Publisher", PUBLISHER))
        root.addView(row("Build", buildLabel()))
        root.addView(row("License", LICENSE_NAME))
        root.addView(row("Rust core", NativeBridge.version()))
        root.addView(row("Rust diagnostics", NativeBridge.diagnostics()))
        root.addView(syncStatus)
        root.addView(Button(this).apply {
            text = "Run sync now"
            setOnClickListener {
                HnsSyncForegroundService.start(this@DiagnosticsActivity)
                isEnabled = false
                syncStatus.text = "Sync status: running"
                val running = AtomicBoolean(true)
                thread(name = "hns-sync-status-poll") {
                    while (running.get()) {
                        Thread.sleep(SYNC_STATUS_POLL_MS)
                        val status = NativeBridge.syncStatus(filesDir.absolutePath)
                        runOnUiThread {
                            if (running.get()) {
                                syncStatus.text = "Sync status: running $status"
                            }
                        }
                    }
                }
                thread(name = "hns-sync-now") {
                    val status = NativeBridge.syncOnce(filesDir.absolutePath)
                    running.set(false)
                    runOnUiThread {
                        syncStatus.text = "Sync status: $status"
                        isEnabled = true
                    }
                }
            }
        })
        root.addView(Button(this).apply {
            text = "Clear resolver cache"
            setOnClickListener {
                syncStatus.text = "Sync status: ${NativeBridge.clearResolverCache(filesDir.absolutePath)}"
            }
        })
        root.addView(row("Proxy override", WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE).toString()))
        root.addView(row("Disclaimer", DIAGNOSTIC_DISCLAIMER))
        root.addView(
            linkRow(
                "Donate HNS",
                HNS_DONATION_ADDRESS,
                HNS_DONATION_URI,
                "HNS donation address",
                HNS_DONATION_ADDRESS,
            ),
        )
        root.addView(linkRow("Source code", SOURCE_CODE_URL, SOURCE_CODE_URL, "source code URL", SOURCE_CODE_URL))

        setContentView(
            ScrollView(this).apply {
                addView(root)
            },
        )
    }

    private fun row(label: String, value: String): TextView =
        TextView(this).apply {
            text = "$label: $value"
            textSize = 16f
            setTextIsSelectable(true)
            setPadding(0, 10, 0, 10)
        }

    private fun linkRow(label: String, value: String, uri: String, copyLabel: String, copyText: String): TextView =
        row(label, value).apply {
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

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) "debug demo" else "release"
        return "$channel ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
    }

    private companion object {
        const val PUBLISHER = "Denuo Web, LLC"
        const val LICENSE_NAME = "PolyForm Noncommercial 1.0.0"
        const val DIAGNOSTIC_DISCLAIMER =
            "Experimental diagnostic build. HNS resolution and DANE checks are provided for testing, may fail closed, and are not a financial service. Donations are optional and unlock no features."
        const val HNS_DONATION_ADDRESS = "hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh"
        const val HNS_DONATION_URI =
            "handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh?label=Denuo%20Web%20Handshake%20Browser&message=Handshake%20Browser%20donation"
        const val SOURCE_CODE_URL = "https://github.com/denuoweb/handshake-browser-android"
        const val SYNC_STATUS_POLL_MS = 2_000L
    }
}
