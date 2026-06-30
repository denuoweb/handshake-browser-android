package com.handshake.browser.net

import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class HnsWebSocketBridge(
    private val dataDir: File,
    private val activeMainFrameUrl: () -> String?,
    private val strictHnsMode: () -> Boolean = { false },
    private val hnsGatewayBridge: HnsGatewayBridge = NativeBridge,
    private val callbackHandler: Handler = Handler(Looper.getMainLooper()),
    private val executor: ExecutorService = Executors.newCachedThreadPool(),
) : WebViewCompat.WebMessageListener, Closeable {
    private val sessions = ConcurrentHashMap<Int, NativeHnsWebSocketSession>()
    private val closed = AtomicBoolean(false)

    override fun onPostMessage(
        view: WebView,
        message: WebMessageCompat,
        sourceOrigin: Uri,
        isMainFrame: Boolean,
        replyProxy: JavaScriptReplyProxy,
    ) {
        if (closed.get() || message.type != WebMessageCompat.TYPE_STRING) {
            return
        }
        val data = message.data ?: return
        val payload = runCatching { JSONObject(data) }.getOrNull() ?: return
        when (payload.optString("type")) {
            "open" -> openSession(payload, sourceOrigin.toString(), isMainFrame, replyProxy)
            "send" -> sendSessionPayload(payload)
            "close" -> closeSession(payload)
        }
    }

    fun closeAll(code: Int = CLOSE_GOING_AWAY, reason: String = "page changed") {
        sessions.values.forEach { it.close(code, reason) }
        sessions.clear()
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            closeAll(CLOSE_GOING_AWAY, "browser shutdown")
            executor.shutdownNow()
        }
    }

    private fun openSession(
        payload: JSONObject,
        sourceOrigin: String,
        isMainFrame: Boolean,
        replyProxy: JavaScriptReplyProxy,
    ) {
        val id = payload.optInt("id", -1)
        if (id < 0) {
            return
        }
        if (sessions.size >= MAX_ACTIVE_SESSIONS) {
            emitClose(replyProxy, id, CLOSE_ABNORMAL, "too many HNS WebSockets", false)
            return
        }
        val target = runCatching {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = sourceOrigin,
                activeMainFrameUrl = activeMainFrameUrl(),
                targetUrl = payload.getString("url"),
                isMainFrame = isMainFrame,
            )
        }.getOrElse { error ->
            emitError(replyProxy, id, error.message ?: "HNS WebSocket blocked")
            emitClose(replyProxy, id, CLOSE_ABNORMAL, error.message ?: "HNS WebSocket blocked", false)
            return
        }
        val session = NativeHnsWebSocketSession(
            id = id,
            target = target,
            protocols = payload.optJSONArray("protocols").stringValues(),
            dataDir = dataDir,
            strictHnsMode = strictHnsMode,
            hnsGatewayBridge = hnsGatewayBridge,
            executor = executor,
            emit = { event -> emit(replyProxy, event) },
            onFinished = { sessions.remove(id) },
        )
        if (sessions.putIfAbsent(id, session) != null) {
            emitClose(replyProxy, id, CLOSE_ABNORMAL, "duplicate HNS WebSocket id", false)
            return
        }
        session.start()
    }

    private fun sendSessionPayload(payload: JSONObject) {
        val session = sessions[payload.optInt("id", -1)] ?: return
        when (payload.optString("dataType")) {
            "text" -> session.sendText(payload.optString("data", ""))
            "binary" -> session.sendBinary(
                runCatching { Base64.getDecoder().decode(payload.optString("data", "")) }
                    .getOrDefault(ByteArray(0)),
            )
            else -> session.sendText(payload.optString("data", ""))
        }
    }

    private fun closeSession(payload: JSONObject) {
        val id = payload.optInt("id", -1)
        sessions[id]?.close(
            code = payload.optInt("code", CLOSE_NORMAL),
            reason = payload.optString("reason", ""),
        )
    }

    private fun emit(replyProxy: JavaScriptReplyProxy, event: JSONObject) {
        callbackHandler.post {
            runCatching { replyProxy.postMessage(event.toString()) }
        }
    }

    private fun emitError(replyProxy: JavaScriptReplyProxy, id: Int, reason: String) {
        emit(replyProxy, JSONObject().put("id", id).put("event", "error").put("reason", reason))
    }

    private fun emitClose(replyProxy: JavaScriptReplyProxy, id: Int, code: Int, reason: String, wasClean: Boolean) {
        emit(
            replyProxy,
            JSONObject()
                .put("id", id)
                .put("event", "close")
                .put("code", code)
                .put("reason", reason)
                .put("wasClean", wasClean),
        )
    }

    companion object {
        const val MAX_ACTIVE_SESSIONS = 32
        const val CLOSE_NORMAL = 1000
        const val CLOSE_GOING_AWAY = 1001
        const val CLOSE_ABNORMAL = 1006
    }
}

private class NativeHnsWebSocketSession(
    private val id: Int,
    private val target: HnsWebSocketTarget,
    private val protocols: List<String>,
    private val dataDir: File,
    private val strictHnsMode: () -> Boolean,
    private val hnsGatewayBridge: HnsGatewayBridge,
    private val executor: ExecutorService,
    private val emit: (JSONObject) -> Unit,
    private val onFinished: () -> Unit,
) {
    private val finished = AtomicBoolean(false)
    private val writeLock = Any()
    private var clientWriter: PipedOutputStream? = null
    private var continuationOpcode: Int? = null
    private var continuationPayload: ByteArrayOutputStream? = null
    @Volatile
    private var opened = false

    fun start() {
        val clientInput = PipedInputStream(PIPE_BUFFER_BYTES)
        val clientOutput = PipedOutputStream(clientInput)
        clientWriter = clientOutput
        val tunnelOutput = HnsWebSocketTunnelOutput(
            onHandshake = ::handleHandshake,
            onFrameBytes = ::handleFrameBytes,
            onFailure = ::fail,
        )

        executor.execute {
            try {
                val tunneled = hnsGatewayBridge.httpUpgradeTunnel(
                    dataDir = dataDir.absolutePath,
                    method = "GET",
                    scheme = target.scheme,
                    host = target.host,
                    port = target.port,
                    pathAndQuery = target.pathAndQuery,
                    headers = handshakeHeaders(),
                    clientInput = clientInput,
                    clientOutput = tunnelOutput,
                )
                if (!tunneled && !finished.get()) {
                    fail("HNS WebSocket tunnel failed")
                } else if (!finished.get()) {
                    finishClose(HnsWebSocketBridge.CLOSE_ABNORMAL, "HNS WebSocket closed", false)
                }
            } catch (error: Exception) {
                if (!finished.get()) {
                    fail(error.message ?: "HNS WebSocket tunnel failed")
                }
            }
        }
    }

    fun sendText(text: String) {
        writeFrame(HnsWebSocketFrameCodec.OPCODE_TEXT, text.toByteArray(Charsets.UTF_8))
    }

    fun sendBinary(bytes: ByteArray) {
        writeFrame(HnsWebSocketFrameCodec.OPCODE_BINARY, bytes)
    }

    fun close(code: Int, reason: String) {
        executor.execute {
            runCatching {
                val payload = HnsWebSocketFrameCodec.closePayload(code, reason)
                synchronized(writeLock) {
                    clientWriter?.write(HnsWebSocketFrameCodec.encodeClientFrame(HnsWebSocketFrameCodec.OPCODE_CLOSE, payload))
                    clientWriter?.flush()
                    clientWriter?.close()
                }
            }
            finishClose(code, reason, true)
        }
    }

    private fun writeFrame(opcode: Int, payload: ByteArray) {
        if (finished.get() || !opened) {
            return
        }
        executor.execute {
            runCatching {
                synchronized(writeLock) {
                    clientWriter?.write(HnsWebSocketFrameCodec.encodeClientFrame(opcode, payload))
                    clientWriter?.flush()
                }
            }.onFailure {
                fail("HNS WebSocket send failed")
            }
        }
    }

    private fun handleHandshake(head: ByteArray) {
        val response = HnsWebSocketHandshakeResponse.parse(head)
        if (response.status != 101) {
            fail("HNS WebSocket tunnel returned HTTP ${response.status}")
            return
        }
        opened = true
        emit(
            JSONObject()
                .put("id", id)
                .put("event", "open")
                .put("protocol", response.header("Sec-WebSocket-Protocol").orEmpty()),
        )
    }

    private fun handleFrameBytes(bytes: ByteArray, offset: Int, length: Int) {
        frameParser.append(bytes, offset, length)
    }

    private val frameParser = HnsWebSocketFrameParser { frame ->
        when (frame.opcode) {
            HnsWebSocketFrameCodec.OPCODE_TEXT,
            HnsWebSocketFrameCodec.OPCODE_BINARY,
            -> handleDataFrame(frame)
            HnsWebSocketFrameCodec.OPCODE_CONTINUATION -> handleContinuation(frame)
            HnsWebSocketFrameCodec.OPCODE_PING -> writeFrame(HnsWebSocketFrameCodec.OPCODE_PONG, frame.payload)
            HnsWebSocketFrameCodec.OPCODE_CLOSE -> {
                val code = HnsWebSocketFrameCodec.closeCode(frame.payload) ?: HnsWebSocketBridge.CLOSE_NORMAL
                val reason = HnsWebSocketFrameCodec.closeReason(frame.payload)
                finishClose(code, reason, true)
            }
        }
    }

    private fun handleDataFrame(frame: HnsWebSocketFrame) {
        if (!frame.fin) {
            continuationOpcode = frame.opcode
            continuationPayload = ByteArrayOutputStream().apply { write(frame.payload) }
            return
        }
        emitMessage(frame.opcode, frame.payload)
    }

    private fun handleContinuation(frame: HnsWebSocketFrame) {
        val opcode = continuationOpcode ?: return
        val payload = continuationPayload ?: return
        payload.write(frame.payload)
        if (frame.fin) {
            continuationOpcode = null
            continuationPayload = null
            emitMessage(opcode, payload.toByteArray())
        }
    }

    private fun emitMessage(opcode: Int, payload: ByteArray) {
        val event = JSONObject()
            .put("id", id)
            .put("event", "message")
        if (opcode == HnsWebSocketFrameCodec.OPCODE_TEXT) {
            event.put("dataType", "text")
            event.put("data", payload.toString(Charsets.UTF_8))
        } else {
            event.put("dataType", "binary")
            event.put("data", Base64.getEncoder().encodeToString(payload))
        }
        emit(event)
    }

    private fun fail(reason: String) {
        if (finished.get()) {
            return
        }
        emit(JSONObject().put("id", id).put("event", "error").put("reason", reason))
        finishClose(HnsWebSocketBridge.CLOSE_ABNORMAL, reason, false)
    }

    private fun finishClose(code: Int, reason: String, wasClean: Boolean) {
        if (!finished.compareAndSet(false, true)) {
            return
        }
        runCatching {
            synchronized(writeLock) {
                clientWriter?.close()
                clientWriter = null
            }
        }
        emit(
            JSONObject()
                .put("id", id)
                .put("event", "close")
                .put("code", code)
                .put("reason", reason)
                .put("wasClean", wasClean),
        )
        onFinished()
    }

    private fun handshakeHeaders(): List<Pair<String, String>> {
        val headers = mutableListOf(
            "Host" to target.hostHeader(),
            "Origin" to target.origin,
            "Upgrade" to "websocket",
            "Connection" to "Upgrade",
            "Sec-WebSocket-Key" to websocketKey(),
            "Sec-WebSocket-Version" to "13",
        )
        if (protocols.isNotEmpty()) {
            headers += "Sec-WebSocket-Protocol" to protocols.joinToString(", ")
        }
        if (strictHnsMode()) {
            headers += HNS_GATEWAY_STRICT_MODE_HEADER to "1"
        }
        return headers
    }

    private fun HnsWebSocketTarget.hostHeader(): String {
        val bracketedHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        val defaultPort = if (scheme.equals("wss", ignoreCase = true)) 443 else 80
        return if (port == defaultPort) bracketedHost else "$bracketedHost:$port"
    }

    private fun websocketKey(): String {
        val bytes = ByteArray(16)
        SECURE_RANDOM.nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }

    private companion object {
        const val PIPE_BUFFER_BYTES = 64 * 1024
        val SECURE_RANDOM = java.security.SecureRandom()
    }
}

private class HnsWebSocketTunnelOutput(
    private val onHandshake: (ByteArray) -> Unit,
    private val onFrameBytes: (ByteArray, Int, Int) -> Unit,
    private val onFailure: (String) -> Unit,
) : OutputStream() {
    private val handshake = ByteArrayOutputStream()
    private var handshakeComplete = false

    override fun write(b: Int) {
        val byte = byteArrayOf(b.toByte())
        write(byte, 0, byte.size)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) {
            return
        }
        if (handshakeComplete) {
            onFrameBytes(b, off, len)
            return
        }

        handshake.write(b, off, len)
        val bytes = handshake.toByteArray()
        val headEnd = headerEnd(bytes)
        if (headEnd < 0) {
            if (bytes.size > MAX_HANDSHAKE_BYTES) {
                onFailure("HNS WebSocket handshake response is too large")
            }
            return
        }

        val frameOffset = headEnd + HEADER_END.size
        val head = bytes.copyOfRange(0, frameOffset)
        handshakeComplete = true
        onHandshake(head)
        if (bytes.size > frameOffset) {
            onFrameBytes(bytes, frameOffset, bytes.size - frameOffset)
        }
    }

    private fun headerEnd(bytes: ByteArray): Int {
        for (index in 0..(bytes.size - HEADER_END.size)) {
            if (HEADER_END.indices.all { offset -> bytes[index + offset] == HEADER_END[offset] }) {
                return index
            }
        }
        return -1
    }

    private companion object {
        const val MAX_HANDSHAKE_BYTES = 64 * 1024
        val HEADER_END = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
    }
}

private data class HnsWebSocketHandshakeResponse(
    val status: Int,
    val headers: List<Pair<String, String>>,
) {
    fun header(name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    companion object {
        fun parse(bytes: ByteArray): HnsWebSocketHandshakeResponse {
            val text = bytes.toString(StandardCharsets.ISO_8859_1)
            val lines = text.split("\r\n").filter { it.isNotEmpty() }
            val status = lines.firstOrNull()
                ?.split(' ', limit = 3)
                ?.getOrNull(1)
                ?.toIntOrNull()
                ?: 0
            val headers = lines.drop(1).mapNotNull { line ->
                val separator = line.indexOf(':')
                if (separator <= 0) {
                    null
                } else {
                    line.substring(0, separator).trim() to line.substring(separator + 1).trim()
                }
            }
            return HnsWebSocketHandshakeResponse(status, headers)
        }
    }
}

private fun JSONArray?.stringValues(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return (0 until length())
        .mapNotNull { index -> optString(index).trim().takeIf { it.isNotEmpty() } }
        .filter { isWebSocketProtocolToken(it) }
        .distinctBy { it.lowercase(Locale.US) }
}

private fun isWebSocketProtocolToken(value: String): Boolean {
    if (value.isEmpty()) {
        return false
    }
    return value.all { char ->
        char.code in 0x21..0x7e && char !in HTTP_TOKEN_SEPARATORS
    }
}

private val HTTP_TOKEN_SEPARATORS = setOf('(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t')
