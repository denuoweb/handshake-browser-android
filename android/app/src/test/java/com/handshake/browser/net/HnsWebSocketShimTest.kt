package com.handshake.browser.net

import org.junit.Assert.assertTrue
import org.junit.Test

class HnsWebSocketShimTest {
    @Test
    fun generatedShimTagsAndFiltersDocumentScopedEvents() {
        val script = HnsWebSocketShim.script()

        assertTrue(script.contains("var pageId ="))
        assertTrue(script.contains("type: 'open', pageId: pageId"))
        assertTrue(script.contains("type: 'send', pageId: pageId"))
        assertTrue(script.contains("type: 'close', pageId: pageId"))
        assertTrue(script.contains("if (message.pageId !== pageId) return;"))
    }
}
