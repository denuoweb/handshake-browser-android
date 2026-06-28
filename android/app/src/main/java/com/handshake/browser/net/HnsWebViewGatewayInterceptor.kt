package com.handshake.browser.net

import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import com.handshake.browser.core.HnsHostPolicy
import com.handshake.browser.core.HnsPageResolverPolicy
import com.handshake.browser.core.HnsPageTlsPolicy
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale

class HnsWebViewGatewayInterceptor(
    private val dataDir: File,
    private val hnsGatewayBridge: HnsGatewayBridge = NativeBridge,
    private val allowProxyFallbackForBodyRequests: () -> Boolean = { false },
    private val strictHnsMode: () -> Boolean = { false },
    private val reportAllHnsStatuses: Boolean = false,
    private val onMainFrameHnsStatus: (Int, HnsPageTlsPolicy?, HnsPageResolverPolicy?, String?) -> Unit = { _, _, _, _ -> },
) {
    fun intercept(request: WebResourceRequest): WebResourceResponse? {
        return intercept(
            method = request.method,
            url = request.url.toString(),
            requestHeaders = request.requestHeaders.orEmpty(),
            isForMainFrame = request.isForMainFrame,
        )?.toWebResourceResponse()
    }

    internal fun intercept(
        method: String,
        url: String,
        requestHeaders: Map<String, String>,
    ): HnsInterceptedResponse? {
        return intercept(method, url, requestHeaders, false)
    }

    internal fun intercept(
        method: String,
        url: String,
        requestHeaders: Map<String, String>,
        isForMainFrame: Boolean,
    ): HnsInterceptedResponse? {
        val response = interceptInternal(method, url, requestHeaders, MAX_HNS_REDIRECTS)
        if (response != null && (isForMainFrame || reportAllHnsStatuses)) {
            onMainFrameHnsStatus(
                response.statusCode,
                response.hnsTlsPolicy(),
                response.hnsResolverPolicy(),
                response.hnsResolutionTrace(),
            )
        }
        return response
    }

    private fun interceptInternal(
        method: String,
        url: String,
        requestHeaders: Map<String, String>,
        redirectsRemaining: Int,
    ): HnsInterceptedResponse? {
        val target = HnsWebViewTarget.parse(url) ?: return null
        if (!HnsHostPolicy.requiresHnsResolution(target.host)) {
            return null
        }

        val normalizedMethod = method.uppercase(Locale.US)
        if (normalizedMethod !in BODYLESS_METHODS) {
            if (allowProxyFallbackForBodyRequests()) {
                return null
            }
            GatewayEventLog.record("webview_reject", target.host, 501, "HNS Method Unsupported")
            return plainInterceptResponse(
                statusCode = 501,
                reason = "HNS Method Unsupported",
                detail = "HNS WebView interception only supports bodyless requests.",
            )
        }

        val headers = gatewayHeaders(requestHeaders)
        val response = hnsGatewayBridge.httpResponseBodyFile(
            dataDir = dataDir.absolutePath,
            method = normalizedMethod,
            scheme = target.scheme,
            host = target.host,
            port = target.port,
            pathAndQuery = target.pathAndQuery,
            headers = headers,
            body = ByteArray(0),
        )?.let { fileResponse ->
            parseGatewayHttpFileResponse(fileResponse.head, fileResponse.bodyFile)
                ?.also { recordGatewayStatus(target.host, it, "webview_native_file_response") }
                ?: run {
                    fileResponse.bodyFile.delete()
                    null
                }
        } ?: run {
            val bytes = hnsGatewayBridge.httpResponse(
                dataDir = dataDir.absolutePath,
                method = normalizedMethod,
                scheme = target.scheme,
                host = target.host,
                port = target.port,
                pathAndQuery = target.pathAndQuery,
                headers = headers,
                body = ByteArray(0),
            ) ?: return plainInterceptResponse(
                statusCode = 503,
                reason = "HNS Resolution Unavailable",
                detail = "Native HNS gateway is unavailable.",
            ).also {
                GatewayEventLog.record("webview_gateway_unavailable", target.host, 503, "HNS Resolution Unavailable")
            }
            parseGatewayHttpResponse(bytes)?.also {
                recordGatewayStatus(target.host, it, "webview_native_response")
            } ?: plainInterceptResponse(
                statusCode = 502,
                reason = "HNS Gateway Error",
                detail = "Native HNS gateway returned a malformed response.",
            ).also {
                GatewayEventLog.record("webview_malformed_response", target.host, 502, "HNS Gateway Error")
            }
        }

        return response.followHnsRedirects(
            method = normalizedMethod,
            target = target,
            requestHeaders = requestHeaders,
            redirectsRemaining = redirectsRemaining,
        )
    }

    private fun gatewayHeaders(requestHeaders: Map<String, String>): List<Pair<String, String>> {
        val headers = requestHeaders
            .filterKeys { name -> !isHopByHopOrSyntheticHeader(name) }
            .map { (name, value) -> name to value }
            .filterNot { it.first.equals(HNS_GATEWAY_STRICT_MODE_HEADER, ignoreCase = true) }
        return if (strictHnsMode()) {
            headers + (HNS_GATEWAY_STRICT_MODE_HEADER to "1")
        } else {
            headers
        }
    }

    private fun HnsInterceptedResponse.followHnsRedirects(
        method: String,
        target: HnsWebViewTarget,
        requestHeaders: Map<String, String>,
        redirectsRemaining: Int,
    ): HnsInterceptedResponse {
        if (statusCode !in REDIRECT_STATUS_CODES) {
            return this
        }
        discardBodyFile()
        if (redirectsRemaining <= 0) {
            GatewayEventLog.record("webview_redirect", target.host, 508, "HNS Redirect Loop")
            return plainInterceptResponse(
                statusCode = 508,
                reason = "HNS Redirect Loop",
                detail = "Native HNS gateway exceeded the bounded redirect limit.",
            )
        }

        val location = headerValue("Location") ?: return plainInterceptResponse(
            statusCode = 502,
            reason = "HNS Redirect Invalid",
            detail = "Native HNS gateway returned a redirect without a Location header.",
        ).also {
            GatewayEventLog.record("webview_redirect", target.host, 502, "HNS Redirect Invalid")
        }
        val redirectUrl = target.resolve(location) ?: return plainInterceptResponse(
            statusCode = 502,
            reason = "HNS Redirect Invalid",
            detail = "Native HNS gateway returned an invalid redirect target.",
        ).also {
            GatewayEventLog.record("webview_redirect", target.host, 502, "HNS Redirect Invalid")
        }
        val redirectTarget = HnsWebViewTarget.parse(redirectUrl)
        if (redirectTarget == null || !HnsHostPolicy.requiresHnsResolution(redirectTarget.host)) {
            GatewayEventLog.record("webview_redirect", target.host, 502, "HNS Redirect Unsupported")
            return plainInterceptResponse(
                statusCode = 502,
                reason = "HNS Redirect Unsupported",
                detail = "HNS WebView interception only follows redirects that stay inside HNS resolution policy.",
            )
        }

        return interceptInternal(
            method = redirectedMethod(method, statusCode),
            url = redirectUrl,
            requestHeaders = requestHeaders,
            redirectsRemaining = redirectsRemaining - 1,
        ) ?: plainInterceptResponse(
            statusCode = 502,
            reason = "HNS Redirect Unsupported",
            detail = "Native HNS gateway redirect target is not interceptable.",
        ).also {
            GatewayEventLog.record("webview_redirect", target.host, 502, "HNS Redirect Unsupported")
        }
    }

    private fun recordGatewayStatus(host: String, response: HnsInterceptedResponse, stage: String) {
        if (response.statusCode >= 400) {
            GatewayEventLog.record(stage, host, response.statusCode, response.reason)
        }
    }

    private companion object {
        val BODYLESS_METHODS = setOf("GET", "HEAD")
        val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)
        const val MAX_HNS_REDIRECTS = 5
    }
}

internal data class HnsInterceptedResponse(
    val statusCode: Int,
    val reason: String,
    val mimeType: String,
    val encoding: String?,
    val headers: Map<String, String>,
    val body: ByteArray,
    private val bodyFile: File? = null,
) {
    fun toWebResourceResponse(): WebResourceResponse {
        val webStatusCode = if (statusCode in 100..299 || statusCode in 400..599) {
            statusCode
        } else {
            502
        }
        val webReason = if (webStatusCode == statusCode) reason else "Unsupported Redirect"
        return WebResourceResponse(
            mimeType,
            encoding,
            webStatusCode,
            webReason,
            headers,
            openBodyStream(),
        )
    }

    internal fun openBodyStream(): InputStream =
        bodyFile?.let(::DeletingFileInputStream) ?: ByteArrayInputStream(body)

    internal fun discardBodyFile() {
        bodyFile?.delete()
    }

    fun headerValue(name: String): String? =
        headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    fun hnsTlsPolicy(): HnsPageTlsPolicy? =
        when (headerValue("X-HNS-TLS-Policy")?.lowercase(Locale.US)) {
            "dane" -> HnsPageTlsPolicy.Dane
            "webpki-fallback" -> HnsPageTlsPolicy.WebPkiFallback
            else -> null
        }

    fun hnsResolverPolicy(): HnsPageResolverPolicy? =
        when (headerValue("X-HNS-Resolver-Policy")?.lowercase(Locale.US)) {
            "hns-doh-compat" -> HnsPageResolverPolicy.HnsDohCompatibility
            else -> null
        }

    fun hnsResolutionTrace(): String? =
        headerValue(HNS_RESOLUTION_TRACE_HEADER)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HnsInterceptedResponse) return false

        return statusCode == other.statusCode &&
            reason == other.reason &&
            mimeType == other.mimeType &&
            encoding == other.encoding &&
            headers == other.headers &&
            body.contentEquals(other.body) &&
            bodyFile == other.bodyFile
    }

    override fun hashCode(): Int {
        var result = statusCode
        result = 31 * result + reason.hashCode()
        result = 31 * result + mimeType.hashCode()
        result = 31 * result + (encoding?.hashCode() ?: 0)
        result = 31 * result + headers.hashCode()
        result = 31 * result + body.contentHashCode()
        result = 31 * result + (bodyFile?.hashCode() ?: 0)
        return result
    }
}

private class DeletingFileInputStream(
    private val file: File,
) : FileInputStream(file) {
    override fun close() {
        try {
            super.close()
        } finally {
            file.delete()
        }
    }
}

private data class HnsWebViewTarget(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathAndQuery: String,
) {
    companion object {
        fun parse(url: String): HnsWebViewTarget? {
            val uri = runCatching { URI(url) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase(Locale.US) ?: return null
            if (scheme != "http" && scheme != "https") {
                return null
            }
            val host = uri.httpAuthorityHost() ?: return null
            val port = when {
                uri.port > 0 -> uri.port
                scheme == "https" -> 443
                else -> 80
            }
            val rawPath = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
            val pathAndQuery = if (uri.rawQuery == null) rawPath else "$rawPath?${uri.rawQuery}"
            return HnsWebViewTarget(scheme, host, port, pathAndQuery)
        }
    }

    fun resolve(location: String): String? =
        runCatching { asUri().resolve(location).toString() }.getOrNull()

    private fun asUri(): URI {
        val portPart = when {
            scheme == "http" && port == 80 -> ""
            scheme == "https" && port == 443 -> ""
            else -> ":$port"
        }
        return URI("$scheme://$host$portPart$pathAndQuery")
    }
}

private fun redirectedMethod(method: String, statusCode: Int): String =
    if (statusCode == 303 && method != "HEAD") "GET" else method

private fun parseGatewayHttpResponse(response: ByteArray): HnsInterceptedResponse? {
    val parsed = parseGatewayHttpResponseHead(response) ?: return null
    val body = response.copyOfRange(parsed.bodyStart, response.size)
    return HnsInterceptedResponse(
        parsed.statusCode,
        parsed.reason,
        parsed.mimeType,
        parsed.encoding,
        parsed.headers,
        body,
    )
}

private fun parseGatewayHttpFileResponse(responseHead: ByteArray, bodyFile: File): HnsInterceptedResponse? {
    val parsed = parseGatewayHttpResponseHead(responseHead) ?: return null
    return HnsInterceptedResponse(
        parsed.statusCode,
        parsed.reason,
        parsed.mimeType,
        parsed.encoding,
        parsed.headers,
        ByteArray(0),
        bodyFile,
    )
}

private data class ParsedGatewayHttpHead(
    val statusCode: Int,
    val reason: String,
    val mimeType: String,
    val encoding: String?,
    val headers: Map<String, String>,
    val bodyStart: Int,
)

private fun parseGatewayHttpResponseHead(response: ByteArray): ParsedGatewayHttpHead? {
    val split = response.indexOfHeaderEnd()
    if (split < 0) {
        return null
    }

    val headerText = response.copyOfRange(0, split).toString(StandardCharsets.ISO_8859_1)
    val lines = headerText.split("\r\n")
    val statusParts = lines.firstOrNull()?.split(' ', limit = 3) ?: return null
    if (statusParts.size < 2 || !statusParts[0].startsWith("HTTP/")) {
        return null
    }
    val statusCode = statusParts[1].toIntOrNull()?.takeIf { it in 100..999 } ?: return null
    val reason = statusParts.getOrNull(2)?.ifBlank { null } ?: "OK"
    val headers = linkedMapOf<String, String>()
    for (line in lines.drop(1).filter { it.isNotEmpty() }) {
        val separator = line.indexOf(':')
        if (separator <= 0) {
            return null
        }
        val name = line.substring(0, separator).trim()
        val value = line.substring(separator + 1).trim()
        if (name.isNotEmpty()) {
            headers[name] = value
        }
    }

    val contentType = headers.entries
        .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
        ?.value
    val mimeType = contentType
        ?.substringBefore(';')
        ?.trim()
        ?.takeIf { it.isNotEmpty() }
        ?: "application/octet-stream"
    val encoding = contentType
        ?.split(';')
        ?.drop(1)
        ?.map { it.trim() }
        ?.firstOrNull { it.startsWith("charset=", ignoreCase = true) }
        ?.substringAfter('=')
        ?.trim('"')
        ?.takeIf { it.isNotEmpty() }
    return ParsedGatewayHttpHead(
        statusCode,
        reason,
        mimeType,
        encoding,
        headers,
        split + HEADER_END.size,
    )
}

private fun plainInterceptResponse(
    statusCode: Int,
    reason: String,
    detail: String,
): HnsInterceptedResponse {
    val body = "$statusCode $reason\n$detail\n".toByteArray(StandardCharsets.UTF_8)
    return HnsInterceptedResponse(
        statusCode = statusCode,
        reason = reason,
        mimeType = "text/plain",
        encoding = "utf-8",
        headers = mapOf(
            "Content-Type" to "text/plain; charset=utf-8",
            "Content-Length" to body.size.toString(),
        ),
        body = body,
    )
}

private fun ByteArray.indexOfHeaderEnd(): Int {
    for (index in 0..(size - HEADER_END.size)) {
        if (HEADER_END.indices.all { offset -> this[index + offset] == HEADER_END[offset] }) {
            return index
        }
    }
    return -1
}

private fun isHopByHopOrSyntheticHeader(name: String): Boolean {
    return name.equals("Connection", ignoreCase = true) ||
        name.equals("Proxy-Connection", ignoreCase = true) ||
        name.equals("Transfer-Encoding", ignoreCase = true) ||
        name.equals("Content-Length", ignoreCase = true) ||
        name.equals("Host", ignoreCase = true) ||
        name.equals(HNS_GATEWAY_STRICT_MODE_HEADER, ignoreCase = true)
}

private val HEADER_END = byteArrayOf(
    '\r'.code.toByte(),
    '\n'.code.toByte(),
    '\r'.code.toByte(),
    '\n'.code.toByte(),
)
