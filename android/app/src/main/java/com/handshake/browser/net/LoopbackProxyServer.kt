package com.handshake.browser.net

import com.handshake.browser.core.HnsHostPolicy
import java.io.Closeable
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean

class LoopbackProxyServer(
    private val port: Int,
    private val dataDir: File = File("."),
    private val hnsGatewayBridge: HnsGatewayBridge = NativeBridge,
    private val hnsConnectTerminator: HnsConnectTerminator = LocalTlsHnsConnectTerminator(),
    private val executor: ExecutorService = Executors.newCachedThreadPool(),
) : Closeable {
    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptLoop: Future<*>? = null

    fun start(): Boolean {
        if (!running.compareAndSet(false, true)) {
            return true
        }

        return runCatching {
            val socket = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName(LOOPBACK), port))
            }
            serverSocket = socket
            acceptLoop = executor.submit {
                while (running.get()) {
                    val client = runCatching { socket.accept() }.getOrElse { error ->
                        if (running.get()) error.printStackTrace()
                        null
                    } ?: continue
                    executor.submit { handleClient(client) }
                }
            }
            true
        }.getOrElse {
            running.set(false)
            false
        }
    }

    override fun close() {
        running.set(false)
        runCatching { serverSocket?.close() }
        acceptLoop?.cancel(true)
        executor.shutdownNow()
    }

    fun boundPort(): Int? = serverSocket?.localPort

    private fun handleClient(client: Socket) {
        client.use { clientSocket ->
            runCatching {
                clientSocket.soTimeout = SOCKET_TIMEOUT_MS
                val request = readProxyRequest(clientSocket.getInputStream())
                request.validatedContentLength()
                when (request.line.method.uppercase(Locale.US)) {
                    "CONNECT" -> handleConnect(clientSocket, request)
                    else -> handleHttp(clientSocket, request)
                }
            }.onFailure { error ->
                runCatching {
                    if (error is ProxyHttpException) {
                        writePlainError(clientSocket.getOutputStream(), error.status, error.reason)
                    } else {
                        writePlainError(clientSocket.getOutputStream(), 502, "Bad Gateway")
                    }
                }
            }
        }
    }

    private fun handleConnect(client: Socket, request: ProxyRequest) {
        val target = ConnectTarget.parse(request.line.target)
        if (requiresHnsResolution(target.host)) {
            handleHnsConnect(client, target)
            return
        }
        requireNonHnsHost(target.host)
        Socket().use { origin ->
            origin.connect(InetSocketAddress(target.host, target.port), CONNECT_TIMEOUT_MS)
            client.getOutputStream().write(CONNECT_OK)
            client.getOutputStream().flush()
            tunnel(client, origin)
        }
    }

    private fun handleHnsConnect(client: Socket, target: ConnectTarget) {
        runCatching { hnsConnectTerminator.prepare(target) }.getOrElse {
            throw ProxyHttpException(501, "HNS HTTPS Termination Unavailable")
        }
        client.getOutputStream().write(CONNECT_OK)
        client.getOutputStream().flush()

        val securedClient = runCatching { hnsConnectTerminator.secure(client, target) }.getOrElse {
            return
        }
        securedClient.use { tlsClient ->
            runCatching {
                val tunneledRequest = readProxyRequest(tlsClient.getInputStream())
                tunneledRequest.validatedContentLength()
                val httpTarget = tunneledRequest.line.toConnectedHttpTarget(target)
                if (!requiresHnsResolution(httpTarget.host)) {
                    throw ProxyHttpException(400, "HNS Request Mismatch")
                }
                handleHnsGatewayHttp(tlsClient, tunneledRequest, httpTarget)
            }.onFailure { error ->
                if (error is ProxyHttpException) {
                    writePlainError(tlsClient.getOutputStream(), error.status, error.reason)
                } else {
                    writePlainError(tlsClient.getOutputStream(), 502, "Bad Gateway")
                }
            }
        }
    }

    private fun handleHttp(client: Socket, request: ProxyRequest) {
        val target = request.line.toHttpTarget()
        if (requiresHnsResolution(target.host)) {
            handleHnsGatewayHttp(client, request, target)
            return
        }
        request.rejectTransferEncoding()
        val contentLength = request.validatedContentLength()
        if (request.isProtocolUpgrade()) {
            if (contentLength != 0L) {
                throw ProxyHttpException(400, "Protocol Upgrade Request Invalid")
            }
            handleHttpUpgrade(client, request, target)
            return
        }

        Socket().use { origin ->
            origin.connect(InetSocketAddress(target.host, target.port), CONNECT_TIMEOUT_MS)
            origin.getOutputStream().write(request.toOriginBytes(target))
            copyFixedTo(client.getInputStream(), origin.getOutputStream(), contentLength)
            origin.getOutputStream().flush()
            copy(origin.getInputStream(), client.getOutputStream())
        }
    }

    private fun handleHttpUpgrade(client: Socket, request: ProxyRequest, target: HttpTarget) {
        Socket().use { origin ->
            origin.connect(InetSocketAddress(target.host, target.port), CONNECT_TIMEOUT_MS)
            origin.getOutputStream().write(request.toOriginUpgradeBytes(target))
            origin.getOutputStream().flush()
            tunnel(client, origin)
        }
    }

    private fun handleHnsGatewayHttp(client: Socket, request: ProxyRequest, target: HttpTarget) {
        if (request.isProtocolUpgrade() || target.scheme.equals("ws", ignoreCase = true) || target.scheme.equals("wss", ignoreCase = true)) {
            throw ProxyHttpException(501, "HNS Protocol Upgrade Unsupported")
        }
        request.validateHostHeaderMatches(target)
        val body = readHnsRequestBody(client.getInputStream(), request)
        val gatewayHeaders = request.headersForGateway()
        val fileResponse = hnsGatewayBridge.httpResponseBodyFile(
            dataDir = dataDir.absolutePath,
            method = request.line.method,
            scheme = target.scheme,
            host = target.host,
            port = target.port,
            pathAndQuery = target.pathAndQuery,
            headers = gatewayHeaders,
            body = body,
        )
        if (fileResponse != null) {
            writeGatewayFileResponse(client.getOutputStream(), fileResponse)
            return
        }
        val response = hnsGatewayBridge.httpResponse(
            dataDir = dataDir.absolutePath,
            method = request.line.method,
            scheme = target.scheme,
            host = target.host,
            port = target.port,
            pathAndQuery = target.pathAndQuery,
            headers = gatewayHeaders,
            body = body,
        ) ?: throw ProxyHttpException(503, "HNS Resolution Unavailable")
        client.getOutputStream().write(response)
        client.getOutputStream().flush()
    }

    private fun writeGatewayFileResponse(output: OutputStream, response: HnsGatewayFileResponse) {
        try {
            output.write(response.head)
            FileInputStream(response.bodyFile).use { body ->
                copy(body, output)
            }
            output.flush()
        } finally {
            response.bodyFile.delete()
        }
    }

    private fun readHnsRequestBody(input: InputStream, request: ProxyRequest): ByteArray {
        if (request.hasTransferEncoding()) {
            if (request.hasContentLength()) {
                throw ProxyHttpException(400, "Bad Request Framing")
            }
            if (!request.hasSingleChunkedTransferEncoding()) {
                throw ProxyHttpException(501, "Transfer Encoding Unsupported")
            }
            return readChunked(input, MAX_HNS_BODY_BYTES)
        }

        val contentLength = request.validatedContentLength()
        if (contentLength > MAX_HNS_BODY_BYTES) {
            throw ProxyHttpException(413, "Payload Too Large")
        }
        return readFixed(input, contentLength)
    }

    private fun tunnel(client: Socket, origin: Socket) {
        val upstream = executor.submit {
            copy(client.getInputStream(), origin.getOutputStream())
            runCatching { origin.shutdownOutput() }
        }
        val downstream = executor.submit {
            copy(origin.getInputStream(), client.getOutputStream())
            runCatching { client.shutdownOutput() }
        }
        runCatching { upstream.get() }
        runCatching { downstream.get() }
    }

    private fun readProxyRequest(input: InputStream): ProxyRequest {
        val bytes = ByteArray(MAX_HEADER_BYTES)
        var count = 0
        var matched = 0
        while (count < bytes.size) {
            val next = input.read()
            if (next < 0) throw IOException("unexpected end of request")
            bytes[count++] = next.toByte()
            matched = if (next.toByte() == HEADER_END[matched]) matched + 1 else 0
            if (matched == HEADER_END.size) break
        }
        if (count == bytes.size) throw IOException("headers too large")

        val text = String(bytes, 0, count, StandardCharsets.ISO_8859_1)
        val lines = text.split("\r\n")
        val requestLine = ProxyRequestLine.parse(lines.first())
        val headers = lines.drop(1)
            .takeWhile { it.isNotEmpty() }
            .mapNotNull { line ->
                val index = line.indexOf(':')
                if (index <= 0) null else line.substring(0, index).trim() to line.substring(index + 1).trim()
            }
        return ProxyRequest(requestLine, headers)
    }

    private fun copy(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            output.write(buffer, 0, read)
            output.flush()
        }
    }

    private fun readFixed(input: InputStream, length: Long): ByteArray {
        val output = java.io.ByteArrayOutputStream(length.toInt())
        copyFixedTo(input, output, length)
        return output.toByteArray()
    }

    private fun readChunked(input: InputStream, limit: Long): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        var total = 0L
        while (true) {
            val sizeLine = readAsciiLine(input, MAX_CHUNK_LINE_BYTES)
            val sizeText = sizeLine.substringBefore(';').trim()
            if (sizeText.isEmpty()) {
                throw ProxyHttpException(400, "Bad Chunked Body")
            }
            val size = sizeText.toLongOrNull(16)
                ?.takeIf { it >= 0 }
                ?: throw ProxyHttpException(400, "Bad Chunked Body")
            if (size == 0L) {
                readChunkTrailers(input)
                return output.toByteArray()
            }
            if (size > limit - total) {
                throw ProxyHttpException(413, "Payload Too Large")
            }
            total += size
            copyFixedTo(input, output, size)
            if (input.read() != '\r'.code || input.read() != '\n'.code) {
                throw ProxyHttpException(400, "Bad Chunked Body")
            }
        }
    }

    private fun readChunkTrailers(input: InputStream) {
        var trailerBytes = 0
        while (true) {
            val line = readAsciiLine(input, MAX_CHUNK_LINE_BYTES)
            trailerBytes += line.length
            if (trailerBytes > MAX_CHUNK_TRAILER_BYTES) {
                throw ProxyHttpException(400, "Bad Chunked Body")
            }
            if (line.isEmpty()) {
                return
            }
        }
    }

    private fun readAsciiLine(input: InputStream, maxBytes: Int): String {
        val bytes = java.io.ByteArrayOutputStream()
        var previous = -1
        while (bytes.size() < maxBytes) {
            val next = input.read()
            if (next < 0) throw ProxyHttpException(400, "Bad Chunked Body")
            if (previous == '\r'.code && next == '\n'.code) {
                val line = bytes.toByteArray()
                return String(line, 0, line.size - 1, StandardCharsets.ISO_8859_1)
            }
            bytes.write(next)
            previous = next
        }
        throw ProxyHttpException(400, "Bad Chunked Body")
    }

    private fun copyFixedTo(input: InputStream, output: OutputStream, length: Long) {
        var remaining = length
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (read < 0) throw IOException("unexpected end of request body")
            output.write(buffer, 0, read)
            remaining -= read
        }
    }

    private fun writePlainError(output: OutputStream, status: Int, reason: String) {
        val body = "$status $reason\n".toByteArray(StandardCharsets.UTF_8)
        output.write(
            "HTTP/1.1 $status $reason\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${body.size}\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        output.write(body)
        output.flush()
    }

    private fun requireNonHnsHost(host: String) {
        if (requiresHnsResolution(host)) {
            throw ProxyHttpException(501, "HNS HTTPS Unsupported")
        }
    }

    companion object {
        private const val LOOPBACK = "127.0.0.1"
        private const val MAX_HEADER_BYTES = 64 * 1024
        private const val MAX_HNS_BODY_BYTES = 1024 * 1024L
        private const val MAX_CHUNK_LINE_BYTES = 8 * 1024
        private const val MAX_CHUNK_TRAILER_BYTES = 64 * 1024
        private const val COPY_BUFFER_BYTES = 16 * 1024
        private const val SOCKET_TIMEOUT_MS = 30_000
        private const val CONNECT_TIMEOUT_MS = 10_000
        private val HEADER_END = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
        private val CONNECT_OK = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: HNS Browser\r\n\r\n"
            .toByteArray(StandardCharsets.ISO_8859_1)
    }
}

private class ProxyHttpException(
    val status: Int,
    val reason: String,
) : IOException(reason)

internal data class ProxyRequest(
    val line: ProxyRequestLine,
    val headers: List<Pair<String, String>>,
) {
    fun validateSupportedFraming() {
        rejectTransferEncoding()
        validatedContentLength()
    }

    fun rejectTransferEncoding() {
        if (hasTransferEncoding()) {
            throw ProxyHttpException(501, "Transfer Encoding Unsupported")
        }
    }

    fun hasTransferEncoding(): Boolean =
        headers.any { it.first.equals("Transfer-Encoding", ignoreCase = true) }

    fun hasContentLength(): Boolean =
        headers.any { it.first.equals("Content-Length", ignoreCase = true) }

    fun hasSingleChunkedTransferEncoding(): Boolean {
        val tokens = headers
            .filter { it.first.equals("Transfer-Encoding", ignoreCase = true) }
            .flatMap { it.second.split(',') }
            .map { it.trim().lowercase(Locale.US) }
            .filter { it.isNotEmpty() }
        return tokens.size == 1 && tokens.single() == "chunked"
    }

    fun validatedContentLength(): Long {
        val values = headers
            .filter { it.first.equals("Content-Length", ignoreCase = true) }
            .map { it.second }
        if (values.isEmpty()) {
            return 0L
        }

        val parsed = values.map { value ->
            value.toLongOrNull()
                ?.takeIf { it >= 0 }
                ?: throw ProxyHttpException(400, "Bad Content-Length")
        }
        val first = parsed.first()
        if (parsed.any { it != first }) {
            throw ProxyHttpException(400, "Bad Content-Length")
        }
        return first
    }

    fun validateHostHeaderMatches(target: HttpTarget) {
        val values = headers
            .filter { it.first.equals("Host", ignoreCase = true) }
            .map { it.second }
        if (values.isEmpty()) {
            return
        }
        if (values.size != 1) {
            throw ProxyHttpException(400, "HNS Host Header Mismatch")
        }

        val authority = HostHeaderAuthority.parse(values.single(), target.defaultPort())
            ?: throw ProxyHttpException(400, "HNS Host Header Mismatch")
        if (!sameHost(authority.host, target.host) || authority.port != target.port) {
            throw ProxyHttpException(400, "HNS Host Header Mismatch")
        }
    }

    fun headersForGateway(): List<Pair<String, String>> {
        if (!hasTransferEncoding()) {
            return headers
        }
        return headers
            .filterNot { it.first.equals("Transfer-Encoding", ignoreCase = true) }
            .filterNot { it.first.equals("Trailer", ignoreCase = true) }
            .filterNot { it.first.equals("Content-Length", ignoreCase = true) }
    }

    fun toOriginBytes(target: HttpTarget): ByteArray {
        val request = buildString {
            append(line.method)
            append(' ')
            append(target.pathAndQuery)
            append(' ')
            append(line.version)
            append("\r\n")
            headers
                .filterNot { isHopByHopProxyHeader(it.first) }
                .forEach { (name, value) ->
                    append(name)
                    append(": ")
                    append(value)
                    append("\r\n")
                }
            append("Connection: close\r\n\r\n")
        }
        return request.toByteArray(StandardCharsets.ISO_8859_1)
    }

    fun toOriginUpgradeBytes(target: HttpTarget): ByteArray {
        val request = buildString {
            append(line.method)
            append(' ')
            append(target.pathAndQuery)
            append(' ')
            append(line.version)
            append("\r\n")
            append("Host: ")
            append(target.hostHeader())
            append("\r\n")
            headers
                .filterNot { it.first.equals("Proxy-Connection", ignoreCase = true) }
                .filterNot { it.first.equals("Host", ignoreCase = true) }
                .filterNot { it.first.equals("Content-Length", ignoreCase = true) }
                .forEach { (name, value) ->
                    append(name)
                    append(": ")
                    append(value)
                    append("\r\n")
                }
            append("\r\n")
        }
        return request.toByteArray(StandardCharsets.ISO_8859_1)
    }

    fun isProtocolUpgrade(): Boolean =
        headers.any { it.first.equals("Upgrade", ignoreCase = true) } ||
            headers.any { it.first.equals("Connection", ignoreCase = true) && it.second.hasHeaderToken("upgrade") }

    private fun isHopByHopProxyHeader(name: String): Boolean {
        return name.equals("Proxy-Connection", ignoreCase = true) ||
            name.equals("Connection", ignoreCase = true) ||
            name.equals("Transfer-Encoding", ignoreCase = true)
    }
}

internal data class ProxyRequestLine(
    val method: String,
    val target: String,
    val version: String,
) {
    fun toHttpTarget(): HttpTarget {
        val uri = URI(target)
        val scheme = uri.scheme?.lowercase(Locale.US) ?: "http"
        val host = uri.httpAuthorityHost() ?: throw IOException("absolute-form request target is required")
        val port = when {
            uri.port > 0 -> uri.port
            scheme == "https" || scheme == "wss" -> 443
            else -> 80
        }
        val rawPath = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        val pathAndQuery = if (uri.rawQuery == null) rawPath else "$rawPath?${uri.rawQuery}"
        return HttpTarget(scheme, host, port, pathAndQuery)
    }

    fun toConnectedHttpTarget(connectTarget: ConnectTarget): HttpTarget {
        if (target.startsWith("http://", ignoreCase = true) || target.startsWith("https://", ignoreCase = true)) {
            val absoluteTarget = toHttpTarget()
            if (
                absoluteTarget.scheme != "https" ||
                !sameHost(absoluteTarget.host, connectTarget.host) ||
                absoluteTarget.port != connectTarget.port
            ) {
                throw ProxyHttpException(400, "HNS Request Mismatch")
            }
            return absoluteTarget
        }
        if (!target.startsWith("/")) {
            throw ProxyHttpException(400, "HNS Request Mismatch")
        }
        return HttpTarget("https", connectTarget.host, connectTarget.port, target)
    }

    companion object {
        fun parse(line: String): ProxyRequestLine {
            val parts = line.split(' ', limit = 3)
            if (parts.size != 3 || !parts[2].startsWith("HTTP/")) {
                throw IOException("invalid request line")
            }
            return ProxyRequestLine(parts[0], parts[1], parts[2])
        }
    }
}

internal data class HttpTarget(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathAndQuery: String,
) {
    fun defaultPort(): Int {
        return if (scheme.equals("https", ignoreCase = true) || scheme.equals("wss", ignoreCase = true)) {
            443
        } else {
            80
        }
    }

    fun hostHeader(): String {
        val bracketedHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        return if (port == defaultPort()) bracketedHost else "$bracketedHost:$port"
    }
}

private data class HostHeaderAuthority(
    val host: String,
    val port: Int,
) {
    companion object {
        fun parse(value: String, defaultPort: Int): HostHeaderAuthority? {
            val authority = value.trim()
            if (authority.isEmpty()) {
                return null
            }
            if (authority.startsWith("[")) {
                val close = authority.indexOf(']')
                if (close <= 0) return null
                val host = authority.substring(1, close)
                val suffix = authority.substring(close + 1)
                val port = if (suffix.isEmpty()) {
                    defaultPort
                } else {
                    if (!suffix.startsWith(":")) return null
                    suffix.drop(1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
                }
                return HostHeaderAuthority(host, port)
            }

            val separator = authority.lastIndexOf(':')
            if (separator < 0) {
                return HostHeaderAuthority(authority, defaultPort)
            }
            if (authority.indexOf(':') != separator) {
                return null
            }
            val host = authority.substring(0, separator)
            if (host.isEmpty()) {
                return null
            }
            val port = authority.substring(separator + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            return HostHeaderAuthority(host, port)
        }
    }
}

data class ConnectTarget(
    val host: String,
    val port: Int,
) {
    companion object {
        fun parse(authority: String): ConnectTarget {
            if (authority.startsWith("[")) {
                val close = authority.indexOf(']')
                if (close <= 0) throw IOException("invalid IPv6 authority")
                val host = authority.substring(1, close)
                val suffix = authority.substring(close + 1)
                val port = if (suffix.isEmpty()) {
                    443
                } else {
                    if (!suffix.startsWith(":")) throw IOException("invalid authority")
                    suffix.drop(1).toIntOrNull() ?: throw IOException("invalid port")
                }
                return ConnectTarget(host, port)
            }

            val separator = authority.lastIndexOf(':')
            if (separator < 0 || authority.indexOf(':') != separator) {
                return ConnectTarget(authority, 443)
            }

            val host = authority.substring(0, separator)
            val port = authority.substring(separator + 1).toIntOrNull() ?: throw IOException("invalid port")
            return ConnectTarget(host, port)
        }
    }
}

internal fun requiresHnsResolution(host: String): Boolean {
    return HnsHostPolicy.requiresHnsResolution(host)
}

private fun sameHost(left: String, right: String): Boolean =
    left.trim().trimEnd('.').lowercase(Locale.US) == right.trim().trimEnd('.').lowercase(Locale.US)

private fun String.hasHeaderToken(expected: String): Boolean =
    split(',').any { token -> token.trim().equals(expected, ignoreCase = true) }
