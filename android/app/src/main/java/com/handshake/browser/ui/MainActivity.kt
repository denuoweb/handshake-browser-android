package com.handshake.browser.ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebChromeClient
import android.webkit.SslErrorHandler
import android.webkit.URLUtil
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.net.http.SslError
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.core.content.ContextCompat
import androidx.webkit.ServiceWorkerControllerCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebViewRenderProcess
import androidx.webkit.WebViewRenderProcessClient
import com.handshake.browser.BuildConfig
import com.handshake.browser.R
import com.handshake.browser.core.BrowserSecurityPolicy
import com.handshake.browser.core.BrowserTargetKind
import com.handshake.browser.core.BrowserUrlClassifier
import com.handshake.browser.core.HnsPageResolverPolicy
import com.handshake.browser.core.HnsPageTlsPolicy
import com.handshake.browser.core.SecurityState
import com.handshake.browser.net.GatewayEventLog
import com.handshake.browser.net.HnsProxyController
import com.handshake.browser.net.HnsServiceWorkerGatewayClient
import com.handshake.browser.net.HnsSyncProgress
import com.handshake.browser.net.HnsSyncForegroundService
import com.handshake.browser.net.HnsSyncSnapshot
import com.handshake.browser.net.HnsWebSocketBridge
import com.handshake.browser.net.HnsWebSocketShim
import com.handshake.browser.net.HnsWebViewGatewayInterceptor
import com.handshake.browser.net.HnsWebViewSslErrorPolicy
import com.handshake.browser.net.LoopbackProxyServer
import com.handshake.browser.net.NativeBridge
import java.util.Locale
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
    private lateinit var hamburgerButton: TextView
    private lateinit var syncProgressBar: ProgressBar
    private lateinit var syncProgressStats: TextView
    private lateinit var pageProgressBar: ProgressBar
    private lateinit var proxyController: HnsProxyController
    private lateinit var hnsWebSocketBridge: HnsWebSocketBridge
    private var loopbackProxyServer: LoopbackProxyServer? = null
    private lateinit var assetLoader: WebViewAssetLoader
    private lateinit var webViewGatewayInterceptor: HnsWebViewGatewayInterceptor
    private var proxyAvailable: Boolean = false
    private var currentTargetKind: BrowserTargetKind? = null
    private var mainFrameHnsStatusCode: Int? = null
    private var mainFrameHnsTlsPolicy: HnsPageTlsPolicy? = null
    private var mainFrameHnsResolverPolicy: HnsPageResolverPolicy? = null
    private var mainFrameHnsTraceJson: String? = null
    private var lastSyncSnapshot: HnsSyncSnapshot? = null
    private var syncReceiverRegistered: Boolean = false
    private var activityStarted: Boolean = false
    private var activityDestroyed: Boolean = false
    private var proxyOverrideApplied: Boolean = false
    private var proxyOverrideClearing: Boolean = false
    private var proxyStartPending: Boolean = false
    private var proxyGatewayPort: Int? = null
    private var proxyScopedHost: String? = null
    @Volatile
    private var activeMainFrameUrl: String? = null
    private var pageIsLoading: Boolean = false
    private var pageLoadProgress: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        GatewayEventLog.configureAppStorage(filesDir)
        proxyController = HnsProxyController(this)
        hnsWebSocketBridge = HnsWebSocketBridge(
            dataDir = filesDir,
            activeMainFrameUrl = { activeMainFrameUrl },
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            callbackHandler = mainHandler,
        )
        webViewGatewayInterceptor = HnsWebViewGatewayInterceptor(
            dataDir = filesDir,
            allowProxyFallbackForBodyRequests = { proxyAvailable },
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            reportAllHnsStatuses = true,
            onMainFrameHnsStatus = { statusCode, tlsPolicy, resolverPolicy, traceJson ->
                runOnUiThread {
                    if (mainFrameHnsStatusCode == null) {
                        applyMainFrameHnsStatus(statusCode, tlsPolicy, resolverPolicy, traceJson)
                    }
                }
            },
        )
        assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
        configureServiceWorkerInterception()
        requestNotificationPermissionIfNeeded()

        omnibox = EditText(this).apply {
            hint = getString(R.string.omnibox_hint)
            setSingleLine(true)
            textSize = 16f
            minHeight = dp(48)
            imeOptions = EditorInfo.IME_ACTION_GO
            setSelectAllOnFocus(true)
            setOnEditorActionListener { _, actionId, event ->
                val decision = omniboxEditorDecision(actionId, event?.keyCode, event?.action)
                if (decision.submit) {
                    loadFromInput()
                }
                decision.consume
            }
        }

        securityLabel = TextView(this).apply {
            gravity = Gravity.CENTER
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
            textSize = 13f
            minWidth = dp(88)
            maxWidth = dp(132)
            setPadding(18, 0, 18, 0)
            setTextColor(Color.rgb(28, 71, 75))
            text = getString(R.string.security_syncing)
            contentDescription = getString(R.string.security_status_content_description)
            isClickable = true
            isFocusable = true
            applyScreenSelectableBackground()
            setOnClickListener { openResolverTrace() }
        }

        syncProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = SYNC_PROGRESS_MAX
            isIndeterminate = true
        }
        syncProgressStats = TextView(this).apply {
            setPadding(16, 0, 16, 8)
            setTextColor(Color.rgb(68, 68, 68))
            textSize = 12f
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
            text = HnsSyncProgress.fromJson(null).summary()
        }
        pageProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = PAGE_PROGRESS_MAX
            progress = 0
            visibility = View.GONE
        }

        webView = WebView(this).apply {
            BrowserWebViewHardening.applyTo(this, allowJavaScript = true)
            webViewClient = BrowserClient()
            webChromeClient = BrowserChromeClient()
            setDownloadListener { url, userAgent, contentDisposition, mimeType, _ ->
                handleDownload(url, userAgent, contentDisposition, mimeType)
            }
        }
        configureHnsWebSocketBridge()
        configureRendererRecovery()

        BrowserCookiePreferences.applyTo(webView)

        val toolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(8, 0, 8, 0)
            addView(securityLabel, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(omnibox, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
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
            loadInitialPage(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.getStringExtra(EXTRA_LOAD_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?.let { loadTarget(classifier.classify(it)) }
    }

    override fun onStart() {
        super.onStart()
        activityStarted = true
        BrowserCookiePreferences.applyTo(webView)
        startLoopbackGateway()
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
        activityStarted = false
        stopSyncStatusPolling()
        unregisterSyncSnapshotReceiver()
        stopLoopbackGateway()
        super.onStop()
    }

    override fun onDestroy() {
        activityDestroyed = true
        stopLoopbackGateway()
        hnsWebSocketBridge.close()
        syncStatusExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun createLoopbackGateway(): LoopbackProxyServer =
        LoopbackProxyServer(
            EPHEMERAL_GATEWAY_PORT,
            filesDir,
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            enforceHnsHostScope = true,
            scopedHnsHost = { currentHnsProxyHost() },
            onHnsStatus = { host, statusCode, tlsPolicy, resolverPolicy, traceJson ->
                runOnUiThread {
                    if (isActiveMainFrameHost(host) && mainFrameHnsStatusCode == null) {
                        applyMainFrameHnsStatus(statusCode, tlsPolicy, resolverPolicy, traceJson)
                    }
                }
            },
        )

    private fun startLoopbackGateway() {
        if (activityDestroyed) {
            return
        }
        if (proxyOverrideClearing) {
            proxyStartPending = true
            return
        }
        if (loopbackProxyServer != null) {
            return
        }
        if (currentHnsProxyHost() == null) {
            proxyStartPending = false
            return
        }

        val gateway = createLoopbackGateway()
        loopbackProxyServer = gateway
        val gatewayStarted = gateway.start()
        val gatewayPort = gateway.boundPort()
        if (gatewayStarted && gatewayPort != null) {
            proxyGatewayPort = gatewayPort
            refreshLoopbackProxyScope()
        } else {
            if (loopbackProxyServer === gateway) {
                loopbackProxyServer = null
            }
            proxyAvailable = false
            proxyGatewayPort = null
            proxyScopedHost = null
            gateway.close()
            refreshSecurityState()
        }
    }

    private fun refreshLoopbackProxyScope() {
        val hnsHost = currentHnsProxyHost()
        if (proxyOverrideClearing) {
            proxyStartPending = hnsHost != null
            return
        }
        if (hnsHost == null) {
            stopLoopbackGateway()
            return
        }

        val gateway = loopbackProxyServer
        if (gateway == null) {
            startLoopbackGateway()
            return
        }
        val gatewayPort = proxyGatewayPort ?: gateway.boundPort() ?: return
        if (proxyOverrideApplied && proxyAvailable && proxyScopedHost == hnsHost) {
            return
        }

        proxyController.applyLoopbackProxy(gatewayPort, hnsHost) { applied ->
            if (loopbackProxyServer !== gateway || currentHnsProxyHost() != hnsHost) {
                return@applyLoopbackProxy
            }
            proxyAvailable = applied
            proxyOverrideApplied = applied
            proxyScopedHost = if (applied) hnsHost else null
            if (applied) {
                refreshSecurityState()
            } else {
                stopLoopbackGateway()
            }
        }
    }

    private fun stopLoopbackGateway() {
        val gateway = loopbackProxyServer
        val shouldClearProxy = gateway != null || proxyOverrideApplied
        if (gateway != null) {
            loopbackProxyServer = null
            proxyAvailable = false
            proxyGatewayPort = null
            proxyScopedHost = null
            gateway.close()
            refreshSecurityState()
        } else {
            proxyAvailable = false
            proxyGatewayPort = null
            proxyScopedHost = null
        }

        if (!shouldClearProxy) {
            return
        }
        if (proxyOverrideClearing) {
            return
        }

        proxyOverrideClearing = true
        proxyController.clear {
            proxyOverrideClearing = false
            proxyOverrideApplied = false
            val shouldRestart = proxyStartPending && activityStarted && !activityDestroyed
            proxyStartPending = false
            if (shouldRestart) {
                startLoopbackGateway()
                refreshLoopbackProxyScope()
            } else {
                refreshSecurityState()
            }
        }
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
        if (
            !WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_BASIC_USAGE) ||
            !WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_SHOULD_INTERCEPT_REQUEST)
        ) {
            return
        }

        val serviceWorkerController = ServiceWorkerControllerCompat.getInstance()
        val serviceWorkerSettings = serviceWorkerController.serviceWorkerWebSettings
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_CACHE_MODE)) {
            serviceWorkerSettings.cacheMode = WebSettings.LOAD_NO_CACHE
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_CONTENT_ACCESS)) {
            serviceWorkerSettings.allowContentAccess = false
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_FILE_ACCESS)) {
            serviceWorkerSettings.allowFileAccess = false
        }
        serviceWorkerController.setServiceWorkerClient(
            HnsServiceWorkerGatewayClient(webViewGatewayInterceptor),
        )
    }

    private fun configureHnsWebSocketBridge() {
        if (
            !WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER) ||
            !WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)
        ) {
            return
        }
        WebViewCompat.addWebMessageListener(
            webView,
            HnsWebSocketShim.JS_OBJECT_NAME,
            setOf("*"),
            hnsWebSocketBridge,
        )
        WebViewCompat.addDocumentStartJavaScript(
            webView,
            HnsWebSocketShim.script(),
            setOf("*"),
        )
    }

    private fun configureRendererRecovery() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_VIEW_RENDERER_CLIENT_BASIC_USAGE)) {
            return
        }

        WebViewCompat.setWebViewRenderProcessClient(
            webView,
            ContextCompat.getMainExecutor(this),
            object : WebViewRenderProcessClient() {
                override fun onRenderProcessUnresponsive(
                    view: WebView,
                    renderer: WebViewRenderProcess?,
                ) {
                    Toast.makeText(
                        this@MainActivity,
                        getString(R.string.toast_webview_renderer_unresponsive),
                        Toast.LENGTH_SHORT,
                    ).show()
                    renderer?.terminate()
                }

                override fun onRenderProcessResponsive(
                    view: WebView,
                    renderer: WebViewRenderProcess?,
                ) = Unit
            },
        )
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

    private fun menuButton(): TextView =
        TextView(this).apply {
            hamburgerButton = this
            text = "☰"
            textSize = 30f
            gravity = Gravity.CENTER
            contentDescription = getString(R.string.menu_hamburger_content_description)
            minWidth = dp(48)
            minHeight = dp(48)
            setPadding(dp(12), 0, dp(12), 0)
            setTextColor(Color.rgb(36, 36, 36))
            setOnClickListener { showHamburgerMenu() }
        }

    private fun showHamburgerMenu() {
        val currentUrl = currentPageUrl()

        PopupMenu(this, hamburgerButton).apply {
            menu.add(0, MENU_BACK, 0, getString(R.string.menu_back)).apply {
                setIcon(android.R.drawable.ic_media_previous)
                isEnabled = webView.canGoBack()
            }
            menu.add(0, MENU_FORWARD, 1, getString(R.string.menu_forward)).apply {
                setIcon(android.R.drawable.ic_media_next)
                isEnabled = webView.canGoForward()
            }
            menu.add(0, MENU_REFRESH, 2, getString(R.string.menu_refresh))
                .setIcon(android.R.drawable.ic_popup_sync)
            menu.add(0, MENU_HOME, 3, getString(R.string.menu_home))
                .setIcon(android.R.drawable.ic_menu_upload)
            menu.add(0, MENU_HISTORY, 4, getString(R.string.menu_history))
                .setIcon(android.R.drawable.ic_menu_recent_history)
            menu.add(0, MENU_DOWNLOADS, 5, getString(R.string.menu_downloads))
                .setIcon(android.R.drawable.stat_sys_download_done)
            menu.add(0, MENU_COPY_URL, 6, getString(R.string.menu_copy_current_url)).apply {
                setIcon(android.R.drawable.ic_menu_save)
                isEnabled = currentUrl != null
            }
            menu.add(0, MENU_SHARE_URL, 7, getString(R.string.menu_share_current_url)).apply {
                setIcon(android.R.drawable.ic_menu_share)
                isEnabled = currentUrl != null
            }
            menu.add(0, MENU_SETTINGS, 8, getString(R.string.menu_settings))
                .setIcon(android.R.drawable.ic_menu_manage)
            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    MENU_BACK -> {
                        if (webView.canGoBack()) {
                            webView.goBack()
                        }
                        true
                    }
                    MENU_FORWARD -> {
                        if (webView.canGoForward()) {
                            webView.goForward()
                        }
                        true
                    }
                    MENU_REFRESH -> {
                        webView.reload()
                        true
                    }
                    MENU_HOME -> {
                        loadHomePage()
                        true
                    }
                    MENU_HISTORY -> {
                        openHistory()
                        true
                    }
                    MENU_DOWNLOADS -> {
                        openDownloads()
                        true
                    }
                    MENU_COPY_URL -> {
                        copyCurrentUrl()
                        true
                    }
                    MENU_SHARE_URL -> {
                        shareCurrentUrl()
                        true
                    }
                    MENU_SETTINGS -> {
                        openSettings()
                        true
                    }
                    else -> false
                }
            }
            show()
        }
    }

    private fun loadInitialPage(intent: Intent?) {
        val requestedUrl = intent
            ?.getStringExtra(EXTRA_LOAD_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }
        if (requestedUrl != null) {
            loadTarget(classifier.classify(requestedUrl))
        } else {
            loadHomePage()
        }
    }

    private fun loadHomePage() {
        loadTarget(classifier.classify(BrowserPreferences.homepage(this)))
    }

    private fun loadFromInput() {
        val input = omnibox.text.toString()
        dismissOmniboxKeyboard()
        loadTarget(classifier.classify(input))
    }

    private fun dismissOmniboxKeyboard() {
        val windowToken = omnibox.windowToken
        omnibox.clearFocus()
        webView.requestFocus()
        val inputMethodManager = getSystemService(InputMethodManager::class.java)
        inputMethodManager.hideSoftInputFromWindow(windowToken, 0)
        omnibox.post {
            inputMethodManager.hideSoftInputFromWindow(windowToken, 0)
        }
    }

    private fun loadTarget(target: com.handshake.browser.core.BrowserTarget) {
        omnibox.setText(target.url)
        currentTargetKind = target.kind
        mainFrameHnsStatusCode = null
        mainFrameHnsTlsPolicy = null
        mainFrameHnsResolverPolicy = null
        mainFrameHnsTraceJson = null
        activeMainFrameUrl = target.url
        pageIsLoading = true
        pageLoadProgress = 0
        refreshLoopbackProxyScope()
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

    private fun applyMainFrameHnsStatus(
        statusCode: Int,
        tlsPolicy: HnsPageTlsPolicy?,
        resolverPolicy: HnsPageResolverPolicy?,
        traceJson: String?,
    ) {
        mainFrameHnsStatusCode = statusCode
        mainFrameHnsTlsPolicy = tlsPolicy
        mainFrameHnsResolverPolicy = resolverPolicy
        mainFrameHnsTraceJson = traceJson
        refreshSecurityState()
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
            SecurityState.Loading -> getString(R.string.security_loading)
            SecurityState.HnsVerified -> getString(R.string.security_hns_verified)
            SecurityState.HnsCompatibility -> getString(R.string.security_hns_compat)
            SecurityState.DaneVerified -> getString(R.string.security_dane_verified)
            SecurityState.DaneCompatibility -> getString(R.string.security_dane_compat)
            SecurityState.WebPkiOnly -> getString(R.string.security_webpki)
            SecurityState.MixedPolicy -> getString(R.string.security_hns_webpki)
            SecurityState.ValidationFailed -> getString(R.string.security_failed)
            SecurityState.ProofUnavailable -> getString(R.string.security_proof_unavailable)
        }
    }

    private inner class BrowserClient : WebViewClient() {
        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            hnsWebSocketBridge.closeAll()
            pageIsLoading = true
            pageLoadProgress = pageLoadProgress.coerceAtLeast(5)
            omnibox.setText(url)
            activeMainFrameUrl = url
            currentTargetKind = classifier.classify(url).kind
            mainFrameHnsStatusCode = null
            mainFrameHnsTlsPolicy = null
            mainFrameHnsResolverPolicy = null
            mainFrameHnsTraceJson = null
            refreshLoopbackProxyScope()
            refreshSecurityState()
            refreshPageProgress()
        }

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val requestUrl = request.url.toString()
            val scheme = request.url.scheme?.lowercase(Locale.US)
            if (!request.isForMainFrame) {
                return scheme != null && scheme !in SUBFRAME_ALLOWED_SCHEMES
            }
            if (scheme !in WEB_NAVIGATION_SCHEMES) {
                return handleExternalMainFrameNavigation(request.url)
            }

            activeMainFrameUrl = requestUrl
            val target = classifier.classify(requestUrl)
            currentTargetKind = target.kind
            mainFrameHnsStatusCode = null
            mainFrameHnsTlsPolicy = null
            mainFrameHnsResolverPolicy = null
            mainFrameHnsTraceJson = null
            refreshLoopbackProxyScope()
            refreshSecurityState()
            return false
        }

        override fun shouldInterceptRequest(
            view: WebView,
            request: WebResourceRequest,
        ): WebResourceResponse? {
            assetLoader.shouldInterceptRequest(request.url)?.let { return it }
            val requestUrl = request.url.toString()
            val isMainFrame = request.isForMainFrame || isActiveMainFrameRequest(requestUrl)
            return webViewGatewayInterceptor.intercept(
                method = request.method,
                url = requestUrl,
                requestHeaders = request.requestHeaders.orEmpty(),
                isForMainFrame = isMainFrame,
            )
                ?.toWebResourceResponse()
                ?: super.shouldInterceptRequest(view, request)
        }

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
            activeMainFrameUrl = url
            pageIsLoading = false
            pageLoadProgress = PAGE_PROGRESS_MAX
            recordHistoryEntry(url, view.title)
            refreshSecurityState()
            refreshPageProgress()
        }

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            pageIsLoading = false
            pageLoadProgress = 0
            refreshSecurityState()
            refreshPageProgress()
            Toast.makeText(
                this@MainActivity,
                getString(R.string.toast_webview_renderer_restarted),
                Toast.LENGTH_SHORT,
            ).show()
            stopLoopbackGateway()
            view.destroy()
            finish()
            return true
        }
    }

    private inner class BrowserChromeClient : WebChromeClient() {
        override fun onProgressChanged(view: WebView, newProgress: Int) {
            pageLoadProgress = newProgress.coerceIn(0, PAGE_PROGRESS_MAX)
            if (pageLoadProgress < PAGE_PROGRESS_MAX) {
                pageIsLoading = true
            }
            refreshPageProgress()
        }
    }

    private fun openResolverTrace() {
        startActivity(
            Intent(this, HnsResolverTraceActivity::class.java)
                .putExtra(HnsResolverTraceActivity.EXTRA_URL, omnibox.text.toString())
                .putExtra(HnsResolverTraceActivity.EXTRA_TRACE_JSON, mainFrameHnsTraceJson),
        )
    }

    private fun openSettings() {
        val intent = Intent(this, SettingsActivity::class.java)
        currentPageUrl()?.let { intent.putExtra(SettingsActivity.EXTRA_CURRENT_URL, it) }
        startActivity(intent)
    }

    private fun openHistory() {
        startActivity(Intent(this, HistoryActivity::class.java))
    }

    private fun openDownloads() {
        startActivity(Intent(this, DownloadsActivity::class.java))
    }

    private fun copyCurrentUrl() {
        val url = currentPageUrl()
        if (url == null) {
            Toast.makeText(this, getString(R.string.toast_no_current_url), Toast.LENGTH_SHORT).show()
            return
        }

        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(getString(R.string.clip_current_url), url))
        Toast.makeText(this, getString(R.string.toast_current_url_copied), Toast.LENGTH_SHORT).show()
    }

    private fun shareCurrentUrl() {
        val url = currentPageUrl()
        if (url == null) {
            Toast.makeText(this, getString(R.string.toast_no_current_url), Toast.LENGTH_SHORT).show()
            return
        }

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, url)
        }
        startActivity(Intent.createChooser(sendIntent, getString(R.string.menu_share_current_url)))
    }

    private fun handleExternalMainFrameNavigation(uri: Uri): Boolean {
        val scheme = uri.scheme?.lowercase(Locale.US)
        if (scheme == "about" && uri.toString() == "about:blank") {
            activeMainFrameUrl = uri.toString()
            currentTargetKind = BrowserTargetKind.ExactUrl
            return false
        }
        if (scheme in EXTERNAL_VIEW_SCHEMES) {
            val intent = Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)
            try {
                startActivity(intent)
            } catch (error: ActivityNotFoundException) {
                Toast.makeText(this, getString(R.string.toast_no_app_for_link), Toast.LENGTH_SHORT).show()
            }
            return true
        }

        Toast.makeText(this, getString(R.string.toast_link_not_supported), Toast.LENGTH_SHORT).show()
        return true
    }

    private fun recordHistoryEntry(url: String, title: String?) {
        BrowserHistoryStore.record(this, url, title)
    }

    private fun handleDownload(
        url: String?,
        userAgent: String?,
        contentDisposition: String?,
        mimeType: String?,
    ) {
        val downloadUrl = url?.trim().orEmpty()
        unsupportedDownloadReason(downloadUrl)?.let { reason ->
            Toast.makeText(this, reason, Toast.LENGTH_LONG).show()
            return
        }

        val fileName = URLUtil.guessFileName(downloadUrl, contentDisposition, mimeType)
        val request = DownloadManager.Request(Uri.parse(downloadUrl))
            .setTitle(fileName)
            .setDescription(downloadUrl)
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName)
        if (!mimeType.isNullOrBlank()) {
            request.setMimeType(mimeType)
        }
        if (!userAgent.isNullOrBlank()) {
            request.addRequestHeader("User-Agent", userAgent)
        }

        try {
            val id = getSystemService(DownloadManager::class.java).enqueue(request)
            BrowserDownloadStore.record(this, id, downloadUrl, fileName, mimeType)
            Toast.makeText(this, getString(R.string.toast_download_queued, fileName), Toast.LENGTH_SHORT).show()
        } catch (error: IllegalArgumentException) {
            Toast.makeText(
                this,
                getString(R.string.toast_download_not_supported, error.message ?: "unsupported URL"),
                Toast.LENGTH_LONG,
            ).show()
        } catch (error: SecurityException) {
            Toast.makeText(
                this,
                getString(R.string.toast_download_not_supported, error.message ?: "blocked by Android"),
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    private fun unsupportedDownloadReason(url: String): String? {
        if (url.isBlank()) {
            return getString(R.string.toast_download_not_supported, "missing URL")
        }

        val uri = runCatching { Uri.parse(url) }.getOrNull()
            ?: return getString(R.string.toast_download_not_supported, "invalid URL")
        val scheme = uri.scheme?.lowercase()
        if (scheme == "blob" || scheme == "data") {
            return getString(R.string.toast_download_not_supported, "$scheme URLs are not supported yet")
        }
        if (scheme != "http" && scheme != "https") {
            return getString(R.string.toast_download_not_supported, "only HTTP and HTTPS downloads are supported")
        }
        if (uri.host.equals("appassets.androidplatform.net", ignoreCase = true)) {
            return getString(R.string.toast_download_not_supported, "local app assets cannot be downloaded")
        }
        if (classifier.classify(url).kind == BrowserTargetKind.HnsName) {
            return getString(R.string.toast_download_not_supported, "HNS-resolved downloads are not supported yet")
        }
        return null
    }

    private fun currentPageUrl(): String? =
        webView.url
            ?.trim()
            ?.takeIf { it.isNotBlank() && it != "about:blank" }
            ?: omnibox.text.toString()
                .trim()
                .takeIf { it.isNotBlank() && it != "about:blank" }

    private fun currentHnsProxyHost(): String? {
        val activeUrl = activeMainFrameUrl ?: return null
        val target = classifier.classify(activeUrl)
        if (target.kind != BrowserTargetKind.HnsName) {
            return null
        }
        return target.displayHost
            ?.trim()
            ?.trimEnd('.')
            ?.lowercase(Locale.US)
            ?.takeIf { it.isNotBlank() }
    }

    private fun isActiveMainFrameRequest(url: String): Boolean {
        val activeUrl = activeMainFrameUrl ?: return false
        return url.mainFrameMatchKey() == activeUrl.mainFrameMatchKey()
    }

    private fun isActiveMainFrameHost(host: String): Boolean {
        val activeHost = activeMainFrameUrl
            ?.let { classifier.classify(it).displayHost }
            ?: return false
        return activeHost.equals(host, ignoreCase = true)
    }

    private fun String.mainFrameMatchKey(): String =
        trim().substringBefore('#')

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_LOAD_URL = "com.handshake.browser.LOAD_URL"

        private const val EPHEMERAL_GATEWAY_PORT = 0
        private const val SYNC_PROGRESS_MAX = 1000
        private const val PAGE_PROGRESS_MAX = 100
        private const val SYNC_STATUS_POLL_MS = 2_000L
        private const val REQUEST_NOTIFICATIONS = 1002
        private const val MENU_BACK = 1
        private const val MENU_FORWARD = 2
        private const val MENU_REFRESH = 3
        private const val MENU_HOME = 4
        private const val MENU_HISTORY = 5
        private const val MENU_DOWNLOADS = 6
        private const val MENU_COPY_URL = 7
        private const val MENU_SHARE_URL = 8
        private const val MENU_SETTINGS = 9
        private val WEB_NAVIGATION_SCHEMES = setOf("http", "https")
        private val EXTERNAL_VIEW_SCHEMES = setOf("mailto", "tel", "sms", "geo")
        private val SUBFRAME_ALLOWED_SCHEMES = setOf("http", "https", "about", "data", "blob")
    }
}

internal data class OmniboxEditorDecision(
    val submit: Boolean,
    val consume: Boolean,
)

internal fun omniboxEditorDecision(
    actionId: Int,
    keyCode: Int?,
    keyAction: Int?,
): OmniboxEditorDecision {
    val enterKey = keyCode == KeyEvent.KEYCODE_ENTER
    val submit = actionId == EditorInfo.IME_ACTION_GO ||
        (enterKey && keyAction == KeyEvent.ACTION_DOWN)
    val consume = submit || (enterKey && keyAction == KeyEvent.ACTION_UP)
    return OmniboxEditorDecision(submit = submit, consume = consume)
}
