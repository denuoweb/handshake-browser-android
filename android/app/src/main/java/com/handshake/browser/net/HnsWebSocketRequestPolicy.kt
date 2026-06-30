package com.handshake.browser.net

import com.handshake.browser.core.HnsHostPolicy
import java.net.URI
import java.util.Locale

internal data class HnsWebSocketTarget(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathAndQuery: String,
    val origin: String,
)

internal object HnsWebSocketRequestPolicy {
    fun validate(
        sourceOrigin: String,
        activeMainFrameUrl: String?,
        targetUrl: String,
        isMainFrame: Boolean,
    ): HnsWebSocketTarget {
        if (!isMainFrame) {
            throw HnsWebSocketPolicyException("HNS WebSocket bridge is only available to the main frame.")
        }

        val activeUri = parseUri(activeMainFrameUrl, "active HNS page is unavailable")
        val sourceUri = parseUri(sourceOrigin, "message source origin is unavailable")
        if (!sameOrigin(sourceUri, activeUri)) {
            throw HnsWebSocketPolicyException("message source does not match the active HNS page.")
        }

        val activeScheme = activeUri.scheme?.lowercase(Locale.US)
            ?: throw HnsWebSocketPolicyException("active page scheme is unavailable.")
        if (activeScheme != "https" && activeScheme != "http") {
            throw HnsWebSocketPolicyException("active page scheme is not web-compatible.")
        }
        val activeHost = activeUri.httpAuthorityHost()?.normalizeHost()
            ?: throw HnsWebSocketPolicyException("active page host is unavailable.")
        if (!HnsHostPolicy.requiresHnsResolution(activeHost)) {
            throw HnsWebSocketPolicyException("active page is not an HNS page.")
        }

        val targetUri = parseUri(targetUrl, "target WebSocket URL is invalid")
        val targetScheme = targetUri.scheme?.lowercase(Locale.US)
            ?: throw HnsWebSocketPolicyException("target WebSocket scheme is unavailable.")
        if (targetScheme != "wss" && targetScheme != "ws") {
            throw HnsWebSocketPolicyException("target WebSocket scheme is unsupported.")
        }
        if (activeScheme == "https" && targetScheme == "ws") {
            throw HnsWebSocketPolicyException("secure HNS pages cannot open cleartext WebSockets.")
        }

        val targetHost = targetUri.httpAuthorityHost()?.normalizeHost()
            ?: throw HnsWebSocketPolicyException("target WebSocket host is unavailable.")
        if (!HnsHostPolicy.requiresHnsResolution(targetHost)) {
            throw HnsWebSocketPolicyException("target WebSocket host is not HNS.")
        }
        if (!targetHost.inScopeOf(activeHost)) {
            throw HnsWebSocketPolicyException("target WebSocket host is outside the active HNS page scope.")
        }

        val port = if (targetUri.port > 0) targetUri.port else defaultPort(targetScheme)
        val rawPath = targetUri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        val pathAndQuery = targetUri.rawQuery?.let { "$rawPath?$it" } ?: rawPath
        return HnsWebSocketTarget(
            scheme = targetScheme,
            host = targetHost,
            port = port,
            pathAndQuery = pathAndQuery,
            origin = originHeader(sourceUri),
        )
    }

    private fun parseUri(value: String?, message: String): URI {
        val text = value?.trim()?.takeIf { it.isNotBlank() }
            ?: throw HnsWebSocketPolicyException(message)
        return runCatching { URI(text) }.getOrNull()
            ?: throw HnsWebSocketPolicyException(message)
    }

    private fun sameOrigin(left: URI, right: URI): Boolean {
        val leftScheme = left.scheme?.lowercase(Locale.US) ?: return false
        val rightScheme = right.scheme?.lowercase(Locale.US) ?: return false
        val leftHost = left.httpAuthorityHost()?.normalizeHost() ?: return false
        val rightHost = right.httpAuthorityHost()?.normalizeHost() ?: return false
        return leftScheme == rightScheme &&
            leftHost == rightHost &&
            effectivePort(left, leftScheme) == effectivePort(right, rightScheme)
    }

    private fun originHeader(uri: URI): String {
        val scheme = uri.scheme?.lowercase(Locale.US) ?: "https"
        val host = uri.httpAuthorityHost()?.normalizeHost().orEmpty()
        val port = effectivePort(uri, scheme)
        val hostText = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        return if (port == defaultPort(scheme)) {
            "$scheme://$hostText"
        } else {
            "$scheme://$hostText:$port"
        }
    }

    private fun effectivePort(uri: URI, scheme: String): Int =
        if (uri.port > 0) uri.port else defaultPort(scheme)

    private fun defaultPort(scheme: String): Int =
        when (scheme.lowercase(Locale.US)) {
            "https", "wss" -> 443
            else -> 80
        }

    private fun String.normalizeHost(): String =
        trim().trimEnd('.').lowercase(Locale.US)

    private fun String.inScopeOf(scope: String): Boolean =
        this == scope || endsWith(".$scope")
}

internal class HnsWebSocketPolicyException(message: String) : IllegalArgumentException(message)
