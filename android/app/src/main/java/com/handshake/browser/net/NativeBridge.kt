package com.handshake.browser.net

import java.io.File

interface HnsGatewayBridge {
    fun httpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): ByteArray?

    fun httpResponseBodyFile(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): HnsGatewayFileResponse? = null
}

interface HnsSyncBridge {
    fun syncOnce(dataDir: String): String
}

interface LocalTlsCertificateProvider {
    fun localTlsCertificate(host: String): LocalTlsCertificate?
}

data class LocalTlsCertificate(
    val certificateDer: ByteArray,
    val privateKeyPkcs8Der: ByteArray,
    val certificateSha256: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LocalTlsCertificate) return false
        return certificateDer.contentEquals(other.certificateDer) &&
            privateKeyPkcs8Der.contentEquals(other.privateKeyPkcs8Der) &&
            certificateSha256.contentEquals(other.certificateSha256)
    }

    override fun hashCode(): Int {
        var result = certificateDer.contentHashCode()
        result = 31 * result + privateKeyPkcs8Der.contentHashCode()
        result = 31 * result + certificateSha256.contentHashCode()
        return result
    }
}

data class HnsGatewayFileResponse(
    val head: ByteArray,
    val bodyFile: File,
)

object NativeBridge : HnsGatewayBridge, HnsSyncBridge, LocalTlsCertificateProvider {
    val isLoaded: Boolean = runCatching {
        System.loadLibrary("hns_browser_ffi")
    }.isSuccess

    fun version(): String = if (isLoaded) {
        nativeVersion()
    } else {
        "rust-core-unavailable"
    }

    fun diagnostics(): String = if (isLoaded) {
        nativeDiagnostics()
    } else {
        """{"core":"unavailable","version":"unavailable","features":[],"securityDefault":"fail-closed"}"""
    }

    @Synchronized
    override fun syncOnce(dataDir: String): String = if (isLoaded) {
        nativeSyncOnce(dataDir)
    } else {
        unavailableSyncJson()
    }

    fun syncStatus(dataDir: String): String = if (isLoaded) {
        nativeSyncStatus(dataDir)
    } else {
        unavailableSyncJson()
    }

    fun clearResolverCache(dataDir: String): String = if (isLoaded) {
        nativeClearResolverCache(dataDir)
    } else {
        unavailableSyncJson("rust-core-unavailable")
    }

    override fun localTlsCertificate(host: String): LocalTlsCertificate? = if (isLoaded) {
        nativeLocalTlsCertificate(host)?.let(::parseLocalTlsCertificateBundle)
    } else {
        null
    }

    override fun httpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): ByteArray? = if (isLoaded) {
        nativeGatewayHttpResponse(
            dataDir,
            method,
            scheme,
            host,
            port,
            pathAndQuery,
            serializeHeaders(headers),
            body,
        )
    } else {
        null
    }

    override fun httpResponseBodyFile(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): HnsGatewayFileResponse? {
        if (!isLoaded) {
            return null
        }
        val responseDir = File(dataDir, "hns/response-bodies")
        if (!responseDir.exists() && !responseDir.mkdirs()) {
            return null
        }
        val bodyFile = runCatching {
            File.createTempFile("hns-gateway-", ".body", responseDir)
        }.getOrNull() ?: return null
        val head = nativeGatewayHttpResponseBodyToFile(
            dataDir,
            method,
            scheme,
            host,
            port,
            pathAndQuery,
            serializeHeaders(headers),
            body,
            bodyFile.absolutePath,
        )
        if (head == null || !bodyFile.exists()) {
            bodyFile.delete()
            return null
        }
        return HnsGatewayFileResponse(head, bodyFile)
    }

    private external fun nativeVersion(): String

    private external fun nativeDiagnostics(): String

    private external fun nativeSyncOnce(dataDir: String): String

    private external fun nativeSyncStatus(dataDir: String): String

    private external fun nativeClearResolverCache(dataDir: String): String

    private external fun nativeLocalTlsCertificate(host: String): ByteArray?

    private external fun nativeGatewayHttpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        body: ByteArray,
    ): ByteArray?

    private external fun nativeGatewayHttpResponseBodyToFile(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        body: ByteArray,
        bodyPath: String,
    ): ByteArray?

    private fun serializeHeaders(headers: List<Pair<String, String>>): String = buildString {
        headers.forEach { (name, value) ->
            append(name)
            append(": ")
            append(value)
            append("\r\n")
        }
    }

    private fun parseLocalTlsCertificateBundle(bundle: ByteArray): LocalTlsCertificate? {
        var offset = 0

        fun readLength(): Int? {
            if (offset + 4 > bundle.size) return null
            val length = (
                ((bundle[offset].toInt() and 0xff) shl 24) or
                    ((bundle[offset + 1].toInt() and 0xff) shl 16) or
                    ((bundle[offset + 2].toInt() and 0xff) shl 8) or
                    (bundle[offset + 3].toInt() and 0xff)
                )
            offset += 4
            if (length < 0 || length > bundle.size - offset) return null
            return length
        }

        fun readBytes(length: Int): ByteArray {
            val value = bundle.copyOfRange(offset, offset + length)
            offset += length
            return value
        }

        val certificateLength = readLength() ?: return null
        val certificateDer = readBytes(certificateLength)
        val keyLength = readLength() ?: return null
        val keyDer = readBytes(keyLength)
        if (offset + LOCAL_TLS_FINGERPRINT_BYTES != bundle.size) return null
        val fingerprint = readBytes(LOCAL_TLS_FINGERPRINT_BYTES)
        return LocalTlsCertificate(certificateDer, keyDer, fingerprint)
    }

    private fun unavailableSyncJson(error: String = "rust-core-unavailable"): String =
        """{"status":"error","attempted":0,"successful":0,"accepted":0,"failed":0,"peerCount":0,"peerGroups":0,"bestHeight":null,"bestPeerHeight":null,"estimatedTipHeight":null,"resourceCacheEntries":0,"resourceCacheBytes":0,"resourceCacheEvicted":0,"error":"$error","failures":[]}"""

    private const val LOCAL_TLS_FINGERPRINT_BYTES = 32
}
