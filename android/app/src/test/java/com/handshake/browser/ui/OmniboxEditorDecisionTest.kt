package com.handshake.browser.ui

import android.view.KeyEvent
import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OmniboxEditorDecisionTest {
    @Test
    fun goActionSubmitsAndConsumes() {
        val decision = omniboxEditorDecision(EditorInfo.IME_ACTION_GO, null, null)

        assertTrue(decision.submit)
        assertTrue(decision.consume)
    }

    @Test
    fun enterKeyDownSubmitsAndConsumes() {
        val decision = omniboxEditorDecision(
            actionId = 0,
            keyCode = KeyEvent.KEYCODE_ENTER,
            keyAction = KeyEvent.ACTION_DOWN,
        )

        assertTrue(decision.submit)
        assertTrue(decision.consume)
    }

    @Test
    fun enterKeyUpOnlyConsumes() {
        val decision = omniboxEditorDecision(
            actionId = 0,
            keyCode = KeyEvent.KEYCODE_ENTER,
            keyAction = KeyEvent.ACTION_UP,
        )

        assertFalse(decision.submit)
        assertTrue(decision.consume)
    }

    @Test
    fun unrelatedActionPassesThrough() {
        val decision = omniboxEditorDecision(
            actionId = 0,
            keyCode = KeyEvent.KEYCODE_A,
            keyAction = KeyEvent.ACTION_DOWN,
        )

        assertFalse(decision.submit)
        assertFalse(decision.consume)
    }
}
