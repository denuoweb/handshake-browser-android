package com.handshake.browser.net

import com.handshake.browser.core.HnsPageResolverPolicy
import com.handshake.browser.core.HnsPageTlsPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory

class LoopbackProxyServerTest {
    @Before
    fun clearGatewayEvents() {
        GatewayEventLog.clear()
    }

    @Test
    fun parsesConnectRequestLine() {
        val line = ProxyRequestLine.parse("CONNECT example.com:443 HTTP/1.1")

        assertEquals("CONNECT", line.method)
        assertEquals("example.com:443", line.target)
        assertEquals("HTTP/1.1", line.version)
    }

    @Test
    fun parsesConnectAuthority() {
        assertEquals(ConnectTarget("example.com", 443), ConnectTarget.parse("example.com:443"))
        assertEquals(ConnectTarget("::1", 8443), ConnectTarget.parse("[::1]:8443"))
    }

    @Test
    fun parsesAbsoluteHttpTarget() {
        val target = ProxyRequestLine.parse("GET http://example.com/path?q=1 HTTP/1.1").toHttpTarget()

        assertEquals("http", target.scheme)
        assertEquals("example.com", target.host)
        assertEquals(80, target.port)
        assertEquals("/path?q=1", target.pathAndQuery)
    }

    @Test
    fun bindsEphemeralLoopbackPort() {
        LoopbackProxyServer(0, hnsGatewayBridge = RecordingGatewayBridge(ByteArray(0))).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            assertTrue(port > 0)
            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                assertTrue(socket.isConnected)
            }
        }
    }

    @Test
    fun parsesDottedHnsAbsoluteHttpTarget() {
        val target = ProxyRequestLine.parse("GET https://welcome.2d/path?q=1 HTTP/1.1").toHttpTarget()

        assertEquals("https", target.scheme)
        assertEquals("welcome.2d", target.host)
        assertEquals(443, target.port)
        assertEquals("/path?q=1", target.pathAndQuery)
    }

    @Test
    fun parsesWebSocketAbsoluteHttpTarget() {
        val target = ProxyRequestLine.parse("GET wss://welcome/socket HTTP/1.1").toHttpTarget()

        assertEquals("wss", target.scheme)
        assertEquals("welcome", target.host)
        assertEquals(443, target.port)
        assertEquals("/socket", target.pathAndQuery)
    }

    @Test
    fun rewritesAbsoluteFormToOriginForm() {
        val request = ProxyRequest(
            line = ProxyRequestLine.parse("GET http://example.com/path?q=1 HTTP/1.1"),
            headers = listOf(
                "Host" to "example.com",
                "Proxy-Connection" to "keep-alive",
                "User-Agent" to "test",
            ),
        )
        val bytes = request.toOriginBytes(request.line.toHttpTarget())
        val rewritten = bytes.toString(Charsets.ISO_8859_1)

        assertEquals("GET /path?q=1 HTTP/1.1", rewritten.lineSequence().first())
        assertFalse(rewritten.contains("Proxy-Connection"))
        assertTrue(rewritten.contains("Connection: close"))
    }

    @Test
    fun hnsSingleLabelRequiresLocalResolution() {
        assertTrue(requiresHnsResolution("welcome"))
        assertTrue(requiresHnsResolution("name."))
    }

    @Test
    fun dottedHnsHostRequiresLocalResolutionWhenTldIsNotCommonIcann() {
        assertTrue(requiresHnsResolution("welcome.2d"))
        assertTrue(requiresHnsResolution("blog.proofofconcept"))
    }

    @Test
    fun icannLocalhostAndIpHostsDoNotRequireHnsResolution() {
        assertFalse(requiresHnsResolution("example.com"))
        assertFalse(requiresHnsResolution("handshake.org"))
        assertFalse(requiresHnsResolution("example.io"))
        assertFalse(requiresHnsResolution("localhost"))
        assertFalse(requiresHnsResolution("example"))
        assertFalse(requiresHnsResolution("invalid"))
        assertFalse(requiresHnsResolution("local"))
        assertFalse(requiresHnsResolution("test"))
        assertFalse(requiresHnsResolution("127.0.0.1"))
        assertFalse(requiresHnsResolution("[::1]"))
    }

    @Test
    fun hnsHttpRequestUsesNativeGatewayBridge() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 503 HNS Resolution Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "POST http://welcome/path?q=1 HTTP/1.1\r\nHost: welcome\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 503 HNS Resolution Unavailable\r\n"))
            }
        }

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "POST",
                "http",
                "welcome",
                80,
                "/path?q=1",
                listOf("Host" to "welcome", "Content-Type" to "text/plain", "Content-Length" to "2"),
                "hi",
            ),
            bridge.calls.single(),
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsGatewayFailureRecordsSanitizedDiagnosticEvent() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 503 HNS Resolution Unavailable\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-event-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "POST http://welcome/private?q=token HTTP/1.1\r\n" +
                            "Host: welcome\r\nContent-Length: 2\r\n\r\nhi"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 503 HNS Resolution Unavailable\r\n"))
            }
        }

        val event = GatewayEventLog.snapshot().single()
        assertEquals("native_response", event.stage)
        assertEquals("welcome", event.host)
        assertEquals(503, event.status)
        assertEquals("HNS_Resolution_Unavailable", event.reason)
        val text = GatewayEventLog.snapshotText()
        assertFalse(text.contains("private"))
        assertFalse(text.contains("token"))
        assertFalse(text.contains("secret"))
        assertFalse(text.contains("hi"))
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsDocumentNavigationReportsMainFrameHnsStatus() {
        val bridge = RecordingGatewayBridge(
            (
                "HTTP/1.1 200 OK\r\n" +
                    "Content-Length: 2\r\n" +
                    "Connection: close\r\n" +
                    "X-HNS-TLS-Policy: dane\r\n" +
                    "X-HNS-Resolver-Policy: hns-doh-compat\r\n" +
                    "$HNS_RESOLUTION_TRACE_HEADER: {\"fallback\":{\"used\":true}}\r\n\r\nok"
                ).toByteArray(StandardCharsets.ISO_8859_1),
        )
        val reported = ArrayBlockingQueue<ReportedHnsStatus>(1)
        val dataDir = createTempDirectory("hns-proxy-main-frame-status-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            onHnsStatus = { host, status, tlsPolicy, resolverPolicy, traceJson ->
                reported.offer(ReportedHnsStatus(host, status, tlsPolicy, resolverPolicy, traceJson))
            },
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "GET http://welcome/ HTTP/1.1\r\n" +
                            "Host: welcome\r\n" +
                            "Accept: text/html,application/xhtml+xml\r\n" +
                            "Sec-Fetch-Mode: navigate\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
            }
        }

        assertEquals(
            ReportedHnsStatus(
                "welcome",
                200,
                HnsPageTlsPolicy.Dane,
                HnsPageResolverPolicy.HnsDohCompatibility,
                """{"fallback":{"used":true}}""",
            ),
            reported.poll(1, TimeUnit.SECONDS),
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsRangeRequestPreservesRangeHeadersToNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-19/100\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-range-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "GET http://welcome/file.bin HTTP/1.1\r\n" +
                            "Host: welcome\r\n" +
                            "Range: bytes=10-19\r\n" +
                            "If-Range: \"abc\"\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 206 Partial Content\r\n"))
            }
        }

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "GET",
                "http",
                "welcome",
                80,
                "/file.bin",
                listOf("Host" to "welcome", "Range" to "bytes=10-19", "If-Range" to "\"abc\""),
                "",
            ),
            bridge.calls.single(),
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsHttpRequestStreamsNativeGatewayBodyFile() {
        val bridge = FileGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
            "test".toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-file-body-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "GET http://welcome/file.bin HTTP/1.1\r\nHost: welcome\r\n\r\n"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertEquals("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest", response)
            }
        }

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "GET",
                "http",
                "welcome",
                80,
                "/file.bin",
                listOf("Host" to "welcome"),
                "",
            ),
            bridge.calls.single(),
        )
        assertFalse(bridge.bodyFile.exists())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsHttpRequestRejectsHostHeaderMismatchBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-host-mismatch-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "GET http://welcome/file.bin HTTP/1.1\r\nHost: othername\r\n\r\n"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 400 HNS Host Header Mismatch\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        val event = GatewayEventLog.snapshot().single()
        assertEquals("proxy_reject", event.stage)
        assertEquals("welcome", event.host)
        assertEquals(400, event.status)
        assertEquals("HNS_Host_Header_Mismatch", event.reason)
        assertFalse(GatewayEventLog.snapshotText().contains("othername"))
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsChunkedPostRequestDecodesBodyBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-chunked-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "POST http://welcome/upload HTTP/1.1\r\n" +
                            "Host: welcome\r\n" +
                            "Content-Type: text/plain\r\n" +
                            "Transfer-Encoding: chunked\r\n\r\n" +
                            "2\r\nhi\r\n" +
                            "1;ext=value\r\n!\r\n" +
                            "0\r\nX-Trailer: ignored\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
            }
        }

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "POST",
                "http",
                "welcome",
                80,
                "/upload",
                listOf("Host" to "welcome", "Content-Type" to "text/plain"),
                "hi!",
            ),
            bridge.calls.single(),
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsChunkedPostRejectsContentLengthAmbiguityBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-chunked-cl-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "POST http://welcome/upload HTTP/1.1\r\n" +
                            "Host: welcome\r\n" +
                            "Content-Length: 0\r\n" +
                            "Transfer-Encoding: chunked\r\n\r\n" +
                            "2\r\nhi\r\n0\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 400 Bad Request Framing\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsChunkedPostRejectsMalformedChunkBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-bad-chunk-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "POST http://welcome/upload HTTP/1.1\r\n" +
                            "Host: welcome\r\n" +
                            "Transfer-Encoding: chunked\r\n\r\n" +
                            "z\r\nhi\r\n0\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 400 Bad Chunked Body\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun strictHnsModeAddsInternalGatewayHeaderAndStripsSpoofedValue() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-strict-mode-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            strictHnsMode = { true },
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "GET http://welcome/path HTTP/1.1\r\n" +
                            "Host: welcome\r\n" +
                            "$HNS_GATEWAY_STRICT_MODE_HEADER: 0\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
            }
        }

        assertEquals(
            listOf(
                "Host" to "welcome",
                HNS_GATEWAY_STRICT_MODE_HEADER to "1",
            ),
            bridge.calls.single().headers,
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsConnectRejectsTunneledHostHeaderMismatchBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-connect-host-mismatch-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            hnsConnectTerminator = PassthroughConnectTerminator,
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n" +
                            "GET /file.bin HTTP/1.1\r\nHost: othername\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 Connection Established\r\n"))
                assertTrue(response.contains("HTTP/1.1 400 HNS Host Header Mismatch\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsConnectFailsClosedBeforeNativeOrSystemResolution() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-connect-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            hnsConnectTerminator = UnavailableConnectTerminator,
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 501 HNS HTTPS Termination Unavailable\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsConnectTerminatesToNativeGatewayWithRequestBody() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-connect-body-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            hnsConnectTerminator = PassthroughConnectTerminator,
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n" +
                            "POST /submit?q=1 HTTP/1.1\r\nHost: welcome\r\nContent-Length: 2\r\n\r\nhi"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 Connection Established\r\n"))
                assertTrue(response.contains("HTTP/1.1 201 Created\r\n"))
            }
        }

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "POST",
                "https",
                "welcome",
                443,
                "/submit?q=1",
                listOf("Host" to "welcome", "Content-Length" to "2"),
                "hi",
            ),
            bridge.calls.single(),
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsConnectRejectsTunneledHostMismatchBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-connect-mismatch-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            hnsConnectTerminator = PassthroughConnectTerminator,
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n" +
                            "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 Connection Established\r\n"))
                assertTrue(response.contains("HTTP/1.1 400 HNS Request Mismatch\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsConnectWebSocketUpgradeFailsClosedBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-connect-websocket-test").toFile()
        LoopbackProxyServer(
            0,
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            hnsConnectTerminator = PassthroughConnectTerminator,
        ).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    (
                        "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n" +
                            "GET /socket HTTP/1.1\r\nHost: welcome\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: test\r\nSec-WebSocket-Version: 13\r\n\r\n"
                        ).toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 200 Connection Established\r\n"))
                assertTrue(response.contains("HTTP/1.1 501 HNS Protocol Upgrade Unsupported\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsPlainWebSocketUpgradeFailsClosedBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-plain-websocket-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "GET ws://welcome/socket HTTP/1.1\r\nHost: welcome\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: test\r\nSec-WebSocket-Version: 13\r\n\r\n"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 501 HNS Protocol Upgrade Unsupported\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun icannPlainWebSocketUpgradePreservesUpgradeHeaders() {
        val received = ArrayBlockingQueue<String>(1)
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { origin ->
            val originThread = Thread {
                origin.accept().use { socket ->
                    val request = readHeaderText(socket)
                    received.offer(request)
                    socket.getOutputStream().write(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                            .toByteArray(StandardCharsets.ISO_8859_1),
                    )
                    socket.getOutputStream().flush()
                }
            }.apply { start() }

            LoopbackProxyServer(0, hnsGatewayBridge = RecordingGatewayBridge(ByteArray(0))).use { proxy ->
                assertTrue(proxy.start())
                val proxyPort = requireNotNull(proxy.boundPort())

                Socket(InetAddress.getByName("127.0.0.1"), proxyPort).use { socket ->
                    socket.getOutputStream().write(
                        (
                            "GET http://127.0.0.1:${origin.localPort}/socket HTTP/1.1\r\n" +
                                "Host: wrong.example\r\n" +
                                "Upgrade: websocket\r\n" +
                                "Connection: keep-alive, Upgrade\r\n" +
                                "Proxy-Connection: keep-alive\r\n" +
                                "Sec-WebSocket-Key: test\r\n" +
                                "Sec-WebSocket-Version: 13\r\n\r\n"
                            ).toByteArray(StandardCharsets.ISO_8859_1),
                    )
                    socket.getOutputStream().flush()

                    val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                    assertTrue(response.startsWith("HTTP/1.1 101 Switching Protocols\r\n"))
                }
            }
            originThread.join(1_000)
        }

        val request = received.poll(1, TimeUnit.SECONDS).orEmpty()
        assertTrue(request.startsWith("GET /socket HTTP/1.1\r\n"))
        assertTrue(request.contains("Host: 127.0.0.1:"))
        assertTrue(request.contains("Upgrade: websocket\r\n"))
        assertTrue(request.contains("Connection: keep-alive, Upgrade\r\n"))
        assertFalse(request.contains("Proxy-Connection"))
        assertFalse(request.contains("Host: wrong.example"))
    }

    @Test
    fun transferEncodedRequestsFailClosedBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-transfer-encoding-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "POST http://welcome/path HTTP/1.1\r\nHost: welcome\r\nTransfer-Encoding: gzip\r\n\r\nhi"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 501 Transfer Encoding Unsupported\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun conflictingContentLengthFailsClosedBeforeNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-proxy-content-length-test").toFile()
        LoopbackProxyServer(0, dataDir = dataDir, hnsGatewayBridge = bridge).use { proxy ->
            assertTrue(proxy.start())
            val port = requireNotNull(proxy.boundPort())

            Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
                socket.getOutputStream().write(
                    "POST http://welcome/path HTTP/1.1\r\nHost: welcome\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nhi!"
                        .toByteArray(StandardCharsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()

                val response = socket.getInputStream().readBytes().toString(StandardCharsets.ISO_8859_1)
                assertTrue(response.startsWith("HTTP/1.1 400 Bad Content-Length\r\n"))
            }
        }

        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    private data class GatewayCall(
        val dataDir: String,
        val method: String,
        val scheme: String,
        val host: String,
        val port: Int,
        val pathAndQuery: String,
        val headers: List<Pair<String, String>>,
        val body: String,
    )

    private data class ReportedHnsStatus(
        val host: String,
        val status: Int,
        val tlsPolicy: HnsPageTlsPolicy?,
        val resolverPolicy: HnsPageResolverPolicy?,
        val traceJson: String?,
    )

    private class RecordingGatewayBridge(
        private val response: ByteArray,
    ) : HnsGatewayBridge {
        val calls = mutableListOf<GatewayCall>()

        override fun httpResponse(
            dataDir: String,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): ByteArray {
            calls += GatewayCall(
                dataDir,
                method,
                scheme,
                host,
                port,
                pathAndQuery,
                headers,
                body.toString(StandardCharsets.ISO_8859_1),
            )
            return response
        }
    }

    private class FileGatewayBridge(
        private val responseHead: ByteArray,
        private val responseBody: ByteArray,
    ) : HnsGatewayBridge {
        val calls = mutableListOf<GatewayCall>()
        lateinit var bodyFile: File

        override fun httpResponse(
            dataDir: String,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): ByteArray {
            error("byte-array fallback should not be used")
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
        ): HnsGatewayFileResponse {
            bodyFile = File.createTempFile("hns-test-", ".body", File(dataDir))
            bodyFile.writeBytes(responseBody)
            calls += GatewayCall(
                dataDir,
                method,
                scheme,
                host,
                port,
                pathAndQuery,
                headers,
                body.toString(StandardCharsets.ISO_8859_1),
            )
            return HnsGatewayFileResponse(responseHead, bodyFile)
        }
    }

    private object PassthroughConnectTerminator : HnsConnectTerminator {
        override fun secure(client: Socket, target: ConnectTarget): Socket = client
    }

    private object UnavailableConnectTerminator : HnsConnectTerminator {
        override fun prepare(target: ConnectTarget) {
            throw IOException("unavailable")
        }

        override fun secure(client: Socket, target: ConnectTarget): Socket = client
    }

    private fun readHeaderText(socket: Socket): String {
        val output = StringBuilder()
        val input = socket.getInputStream()
        var matched = 0
        while (matched < HEADER_END.size) {
            val next = input.read()
            if (next < 0) break
            output.append(next.toChar())
            matched = if (next.toByte() == HEADER_END[matched]) matched + 1 else 0
        }
        return output.toString()
    }

    private val HEADER_END = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
}
