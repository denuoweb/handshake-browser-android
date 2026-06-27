package com.handshake.browser.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.ServiceWorkerController
import android.webkit.SslErrorHandler
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.net.http.SslError
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.core.content.ContextCompat
import com.handshake.browser.BuildConfig
import com.handshake.browser.R
import com.handshake.browser.core.BrowserSecurityPolicy
import com.handshake.browser.core.BrowserTargetKind
import com.handshake.browser.core.BrowserUrlClassifier
import com.handshake.browser.core.HnsPageResolverPolicy
import com.handshake.browser.core.HnsPageTlsPolicy
import com.handshake.browser.core.SecurityState
import com.handshake.browser.net.HnsProxyController
import com.handshake.browser.net.HnsServiceWorkerGatewayClient
import com.handshake.browser.net.HnsSyncProgress
import com.handshake.browser.net.HnsSyncForegroundService
import com.handshake.browser.net.HnsSyncSnapshot
import com.handshake.browser.net.HnsWebViewGatewayInterceptor
import com.handshake.browser.net.HnsWebViewSslErrorPolicy
import com.handshake.browser.net.LoopbackProxyServer
import com.handshake.browser.net.NativeBridge
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {
    private val classifier = BrowserUrlClassifier()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val syncStatusExecutor = Executors.newSingleThreadExecutor()
    @Volatile
    private var syncStatusPolling: Boolean = false
    private val syncStatusPollRunnable = object : Runnable {
        override fun run() {
            pollSyncStatusOnce()
        }
    }
    private val syncSnapshotReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != HnsSyncForegroundService.ACTION_SYNC_SNAPSHOT) {
                return
            }

            val statusJson = intent.getStringExtra(HnsSyncForegroundService.EXTRA_STATUS_JSON) ?: return
            lastSyncSnapshot = HnsSyncSnapshot(
                statusJson = statusJson,
                updatedAtMillis = intent.getLongExtra(
                    HnsSyncForegroundService.EXTRA_UPDATED_AT_MILLIS,
                    System.currentTimeMillis(),
                ),
            )
            refreshSecurityState()
            refreshSyncProgress()
        }
    }
    private lateinit var webView: WebView
    private lateinit var omnibox: EditText
    private lateinit var securityLabel: TextView
    private lateinit var syncProgressBar: ProgressBar
    private lateinit var syncProgressStats: TextView
    private lateinit var pageProgressBar: ProgressBar
    private lateinit var proxyController: HnsProxyController
    private lateinit var loopbackProxyServer: LoopbackProxyServer
    private lateinit var webViewGatewayInterceptor: HnsWebViewGatewayInterceptor
    private var proxyAvailable: Boolean = false
    private var currentTargetKind: BrowserTargetKind? = null
    private var mainFrameHnsStatusCode: Int? = null
    private var mainFrameHnsTlsPolicy: HnsPageTlsPolicy? = null
    private var mainFrameHnsResolverPolicy: HnsPageResolverPolicy? = null
    private var lastSyncSnapshot: HnsSyncSnapshot? = null
    private var syncReceiverRegistered: Boolean = false
    private var pageIsLoading: Boolean = false
    private var pageLoadProgress: Int = 0

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        proxyController = HnsProxyController(this)
        loopbackProxyServer = LoopbackProxyServer(DEFAULT_GATEWAY_PORT, filesDir)
        webViewGatewayInterceptor = HnsWebViewGatewayInterceptor(
            dataDir = filesDir,
            allowProxyFallbackForBodyRequests = { proxyAvailable },
            onMainFrameHnsStatus = { statusCode, tlsPolicy, resolverPolicy ->
                runOnUiThread {
                    mainFrameHnsStatusCode = statusCode
                    mainFrameHnsTlsPolicy = tlsPolicy
                    mainFrameHnsResolverPolicy = resolverPolicy
                    refreshSecurityState()
                }
            },
        )
        configureServiceWorkerInterception()
        requestNotificationPermissionIfNeeded()

        omnibox = EditText(this).apply {
            hint = getString(R.string.omnibox_hint)
            setSingleLine(true)
            imeOptions = EditorInfo.IME_ACTION_GO
            setSelectAllOnFocus(true)
            setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_GO) {
                    loadFromInput()
                    true
                } else {
                    false
                }
            }
        }

        securityLabel = TextView(this).apply {
            gravity = Gravity.CENTER
            setPadding(18, 0, 18, 0)
            setTextColor(Color.rgb(28, 71, 75))
            text = getString(R.string.security_syncing)
        }

        syncProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = SYNC_PROGRESS_MAX
            isIndeterminate = true
        }
        syncProgressStats = TextView(this).apply {
            setPadding(16, 0, 16, 8)
            setTextColor(Color.rgb(68, 68, 68))
            text = HnsSyncProgress.fromJson(null).summary()
        }
        pageProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = PAGE_PROGRESS_MAX
            progress = 0
            visibility = View.GONE
        }

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.loadsImagesAutomatically = true
            settings.mediaPlaybackRequiresUserGesture = true
            webViewClient = BrowserClient()
            webChromeClient = BrowserChromeClient()
        }

        CookieManager.getInstance().setAcceptCookie(true)

        val toolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(8, 0, 8, 0)
            addView(navButton(android.R.drawable.ic_media_previous) { if (webView.canGoBack()) webView.goBack() })
            addView(navButton(android.R.drawable.ic_media_next) { if (webView.canGoForward()) webView.goForward() })
            addView(omnibox, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(securityLabel, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(menuButton())
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            applySystemBarPadding()
            addView(toolbar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(syncProgressBar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(syncProgressStats, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(pageProgressBar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(webView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            ))
        }

        setContentView(root)

        val gatewayStarted = loopbackProxyServer.start()
        proxyController.applyLoopbackProxy(DEFAULT_GATEWAY_PORT) { applied ->
            proxyAvailable = applied && gatewayStarted
            refreshSecurityState()
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        if (savedInstanceState == null) {
            loadTarget(classifier.classify(DEFAULT_HOME))
        }
    }

    override fun onStart() {
        super.onStart()
        registerSyncSnapshotReceiver()
        HnsSyncForegroundService.start(this)
        lastSyncSnapshot = HnsSyncSnapshot(
            statusJson = NativeBridge.syncStatus(filesDir.absolutePath),
            updatedAtMillis = System.currentTimeMillis(),
        )
        refreshSecurityState()
        refreshSyncProgress()
        startSyncStatusPolling()
    }

    override fun onStop() {
        stopSyncStatusPolling()
        unregisterSyncSnapshotReceiver()
        super.onStop()
    }

    override fun onDestroy() {
        proxyController.clear {}
        loopbackProxyServer.close()
        syncStatusExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun registerSyncSnapshotReceiver() {
        if (syncReceiverRegistered) {
            return
        }

        ContextCompat.registerReceiver(
            this,
            syncSnapshotReceiver,
            IntentFilter(HnsSyncForegroundService.ACTION_SYNC_SNAPSHOT),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        syncReceiverRegistered = true
    }

    private fun configureServiceWorkerInterception() {
        ServiceWorkerController.getInstance()
            .setServiceWorkerClient(HnsServiceWorkerGatewayClient(webViewGatewayInterceptor))
    }

    private fun unregisterSyncSnapshotReceiver() {
        if (!syncReceiverRegistered) {
            return
        }

        unregisterReceiver(syncSnapshotReceiver)
        syncReceiverRegistered = false
    }

    private fun startSyncStatusPolling() {
        syncStatusPolling = true
        mainHandler.removeCallbacks(syncStatusPollRunnable)
        mainHandler.postDelayed(syncStatusPollRunnable, SYNC_STATUS_POLL_MS)
    }

    private fun stopSyncStatusPolling() {
        syncStatusPolling = false
        mainHandler.removeCallbacks(syncStatusPollRunnable)
    }

    private fun pollSyncStatusOnce() {
        if (!syncStatusPolling) {
            return
        }

        syncStatusExecutor.execute {
            val snapshot = HnsSyncSnapshot(
                statusJson = NativeBridge.syncStatus(filesDir.absolutePath),
                updatedAtMillis = System.currentTimeMillis(),
            )
            runOnUiThread {
                if (!syncStatusPolling) {
                    return@runOnUiThread
                }
                lastSyncSnapshot = snapshot
                refreshSecurityState()
                refreshSyncProgress()
                mainHandler.postDelayed(syncStatusPollRunnable, SYNC_STATUS_POLL_MS)
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            return
        }

        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
    }

    private fun navButton(icon: Int, action: () -> Unit): ImageButton =
        ImageButton(this).apply {
            setImageResource(icon)
            setBackgroundColor(Color.TRANSPARENT)
            setOnClickListener { action() }
        }

    private fun menuButton(): TextView =
        TextView(this).apply {
            text = "☰"
            textSize = 30f
            gravity = Gravity.CENTER
            setPadding(18, 0, 18, 0)
            setTextColor(Color.rgb(36, 36, 36))
            setOnClickListener { showBrowserMenu(this) }
        }

    private fun showBrowserMenu(anchor: View) {
        PopupMenu(this, anchor).apply {
            menu.add(0, MENU_REFRESH, 0, "Refresh")
            menu.add(0, MENU_DIAGNOSTICS, 1, "Diagnostics")
            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    MENU_REFRESH -> {
                        webView.reload()
                        true
                    }
                    MENU_DIAGNOSTICS -> {
                        startActivity(Intent(this@MainActivity, DiagnosticsActivity::class.java))
                        true
                    }
                    else -> false
                }
            }
            show()
        }
    }

    private fun loadFromInput() {
        loadTarget(classifier.classify(omnibox.text.toString()))
    }

    private fun loadTarget(target: com.handshake.browser.core.BrowserTarget) {
        omnibox.setText(target.url)
        currentTargetKind = target.kind
        mainFrameHnsStatusCode = null
        mainFrameHnsTlsPolicy = null
        mainFrameHnsResolverPolicy = null
        pageIsLoading = true
        pageLoadProgress = 0
        refreshSecurityState()
        refreshPageProgress()
        webView.loadUrl(target.url)
    }

    private fun refreshSecurityState() {
        if (
            pageIsLoading &&
            currentTargetKind == BrowserTargetKind.HnsName &&
            mainFrameHnsStatusCode == null
        ) {
            securityLabel.text = getString(R.string.security_loading)
            return
        }

        setSecurityState(
            BrowserSecurityPolicy.state(
                targetKind = currentTargetKind,
                proxyAvailable = proxyAvailable,
                syncStatusJson = lastSyncSnapshot?.statusJson,
                mainFrameHnsStatusCode = mainFrameHnsStatusCode,
                mainFrameHnsTlsPolicy = mainFrameHnsTlsPolicy,
                mainFrameHnsResolverPolicy = mainFrameHnsResolverPolicy,
            ),
        )
    }

    private fun refreshSyncProgress() {
        if (!::syncProgressBar.isInitialized || !::syncProgressStats.isInitialized) {
            return
        }

        val progress = HnsSyncProgress.fromJson(lastSyncSnapshot?.statusJson)
        val permille = progress.progressPermille()
        syncProgressBar.isIndeterminate = permille == null
        if (permille != null) {
            syncProgressBar.progress = permille
        }
        syncProgressStats.text = progress.summary()
    }

    private fun refreshPageProgress() {
        if (!::pageProgressBar.isInitialized) {
            return
        }

        if (pageIsLoading) {
            pageProgressBar.visibility = View.VISIBLE
            pageProgressBar.progress = pageLoadProgress.coerceIn(0, PAGE_PROGRESS_MAX)
        } else {
            pageProgressBar.progress = PAGE_PROGRESS_MAX
            pageProgressBar.visibility = View.GONE
        }
    }

    private fun setSecurityState(state: SecurityState) {
        securityLabel.text = when (state) {
            SecurityState.Syncing -> getString(R.string.security_syncing)
            SecurityState.HnsVerified -> getString(R.string.security_hns_verified)
            SecurityState.HnsCompatibility -> getString(R.string.security_hns_compat)
            SecurityState.DaneVerified -> getString(R.string.security_dane_verified)
            SecurityState.DaneCompatibility -> getString(R.string.security_dane_compat)
            SecurityState.WebPkiOnly -> getString(R.string.security_webpki)
            SecurityState.MixedPolicy -> getString(R.string.security_hns_webpki)
            SecurityState.ValidationFailed -> getString(R.string.security_failed)
            SecurityState.ProofUnavailable -> "Proof unavailable"
        }
    }

    private inner class BrowserClient : WebViewClient() {
        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            pageIsLoading = true
            pageLoadProgress = pageLoadProgress.coerceAtLeast(5)
            omnibox.setText(url)
            currentTargetKind = classifier.classify(url).kind
            mainFrameHnsStatusCode = null
            mainFrameHnsTlsPolicy = null
            mainFrameHnsResolverPolicy = null
            refreshSecurityState()
            refreshPageProgress()
        }

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val target = classifier.classify(request.url.toString())
            currentTargetKind = target.kind
            mainFrameHnsStatusCode = null
            mainFrameHnsTlsPolicy = null
            mainFrameHnsResolverPolicy = null
            refreshSecurityState()
            return false
        }

        override fun shouldInterceptRequest(
            view: WebView,
            request: WebResourceRequest,
        ) = webViewGatewayInterceptor.intercept(request) ?: super.shouldInterceptRequest(view, request)

        @SuppressLint("WebViewClientOnReceivedSslError")
        override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
            if (HnsWebViewSslErrorPolicy.canProceed(error)) {
                handler.proceed()
            } else {
                handler.cancel()
            }
        }

        override fun onPageFinished(view: WebView, url: String) {
            omnibox.setText(url)
            pageIsLoading = false
            pageLoadProgress = PAGE_PROGRESS_MAX
            refreshSecurityState()
            refreshPageProgress()
        }
    }

    private inner class BrowserChromeClient : WebChromeClient() {
        override fun onProgressChanged(view: WebView, newProgress: Int) {
            pageLoadProgress = newProgress.coerceIn(0, PAGE_PROGRESS_MAX)
            pageIsLoading = pageLoadProgress < PAGE_PROGRESS_MAX
            refreshPageProgress()
        }
    }

    companion object {
        private const val DEFAULT_GATEWAY_PORT = 15353
        private const val DEFAULT_HOME = "https://handshake.org/"
        private const val SYNC_PROGRESS_MAX = 1000
        private const val PAGE_PROGRESS_MAX = 100
        private const val SYNC_STATUS_POLL_MS = 2_000L
        private const val REQUEST_NOTIFICATIONS = 1002
        private const val MENU_REFRESH = 1
        private const val MENU_DIAGNOSTICS = 2
    }
}
