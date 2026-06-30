package com.handshake.browser.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsWebSocketFrameCodecTest {
    @Test
    fun parsesUnmaskedServerTextFrameAcrossChunks() {
        val frames = mutableListOf<HnsWebSocketFrame>()
        val parser = HnsWebSocketFrameParser { frames += it }

        parser.append(byteArrayOf(0x81.toByte()))
        parser.append(byteArrayOf(0x02, 'o'.code.toByte(), 'k'.code.toByte()))

        assertEquals(
            listOf(HnsWebSocketFrame(true, HnsWebSocketFrameCodec.OPCODE_TEXT, "ok".toByteArray())),
            frames,
        )
    }

    @Test
    fun encodesMaskedClientFrame() {
        val encoded = HnsWebSocketFrameCodec.encodeClientFrame(
            HnsWebSocketFrameCodec.OPCODE_TEXT,
            "hi".toByteArray(),
            mask = byteArrayOf(0, 0, 0, 0),
        )

        assertEquals(0x81.toByte(), encoded[0])
        assertEquals(0x82.toByte(), encoded[1])
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), encoded.copyOfRange(2, 6))
        assertEquals("hi", encoded.copyOfRange(6, encoded.size).toString(Charsets.UTF_8))
    }

    @Test
    fun parserUnmasksClientStyleFramesForTests() {
        val frames = mutableListOf<HnsWebSocketFrame>()
        val parser = HnsWebSocketFrameParser { frames += it }
        val encoded = HnsWebSocketFrameCodec.encodeClientFrame(
            HnsWebSocketFrameCodec.OPCODE_TEXT,
            "masked".toByteArray(),
            mask = byteArrayOf(1, 2, 3, 4),
        )

        parser.append(encoded)

        assertEquals(1, frames.size)
        assertEquals("masked", frames.single().payload.toString(Charsets.UTF_8))
    }

    @Test
    fun closePayloadRoundTripsCodeAndReason() {
        val payload = HnsWebSocketFrameCodec.closePayload(1000, "done")

        assertEquals(1000, HnsWebSocketFrameCodec.closeCode(payload))
        assertEquals("done", HnsWebSocketFrameCodec.closeReason(payload))
        assertTrue(payload.size > 2)
    }
}
