package com.handshake.browser.ui

import android.annotation.SuppressLint
import android.webkit.WebSettings
import android.webkit.WebView

internal object BrowserWebViewHardening {
    @SuppressLint("SetJavaScriptEnabled")
    @Suppress("DEPRECATION")
    fun applyTo(webView: WebView, allowJavaScript: Boolean) {
        webView.settings.apply {
            javaScriptEnabled = allowJavaScript
            domStorageEnabled = true
            loadsImagesAutomatically = true
            cacheMode = WebSettings.LOAD_NO_CACHE
            mediaPlaybackRequiresUserGesture = true
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            safeBrowsingEnabled = true
            allowFileAccessFromFileURLs = false
            allowUniversalAccessFromFileURLs = false
            allowFileAccess = false
            allowContentAccess = false
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
        }

        webView.removeJavascriptInterface("accessibility")
        webView.removeJavascriptInterface("accessibilityTraversal")
        webView.removeJavascriptInterface("searchBoxJavaBridge_")
    }
}
