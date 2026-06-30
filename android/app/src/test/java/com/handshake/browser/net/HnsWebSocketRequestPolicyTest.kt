package com.handshake.browser.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HnsWebSocketRequestPolicyTest {
    @Test
    fun sameOriginHnsWssTargetIsAllowed() {
        val target = HnsWebSocketRequestPolicy.validate(
            sourceOrigin = "https://denuoweb",
            activeMainFrameUrl = "https://denuoweb/",
            targetUrl = "wss://denuoweb/ws?echo=1",
            isMainFrame = true,
        )

        assertEquals("wss", target.scheme)
        assertEquals("denuoweb", target.host)
        assertEquals(443, target.port)
        assertEquals("/ws?echo=1", target.pathAndQuery)
        assertEquals("https://denuoweb", target.origin)
    }

    @Test
    fun scopedHnsSubdomainTargetIsAllowed() {
        val target = HnsWebSocketRequestPolicy.validate(
            sourceOrigin = "https://denuoweb",
            activeMainFrameUrl = "https://denuoweb/demo",
            targetUrl = "wss://chat.denuoweb/socket",
            isMainFrame = true,
        )

        assertEquals("chat.denuoweb", target.host)
        assertEquals("/socket", target.pathAndQuery)
    }

    @Test
    fun iframeCallersAreRejected() {
        assertThrows(HnsWebSocketPolicyException::class.java) {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = "https://denuoweb",
                activeMainFrameUrl = "https://denuoweb/",
                targetUrl = "wss://denuoweb/ws",
                isMainFrame = false,
            )
        }
    }

    @Test
    fun sourceOriginMustMatchActivePage() {
        assertThrows(HnsWebSocketPolicyException::class.java) {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = "https://otherhns",
                activeMainFrameUrl = "https://denuoweb/",
                targetUrl = "wss://denuoweb/ws",
                isMainFrame = true,
            )
        }
    }

    @Test
    fun secureHnsPagesCannotOpenCleartextWebSockets() {
        assertThrows(HnsWebSocketPolicyException::class.java) {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = "https://denuoweb",
                activeMainFrameUrl = "https://denuoweb/",
                targetUrl = "ws://denuoweb/ws",
                isMainFrame = true,
            )
        }
    }

    @Test
    fun nonHnsTargetsAreRejected() {
        assertThrows(HnsWebSocketPolicyException::class.java) {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = "https://denuoweb",
                activeMainFrameUrl = "https://denuoweb/",
                targetUrl = "wss://denuoweb.com/ws",
                isMainFrame = true,
            )
        }
    }

    @Test
    fun outOfScopeHnsTargetsAreRejected() {
        assertThrows(HnsWebSocketPolicyException::class.java) {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = "https://denuoweb",
                activeMainFrameUrl = "https://denuoweb/",
                targetUrl = "wss://otherhns/ws",
                isMainFrame = true,
            )
        }
    }
}
