package com.handshake.browser.net

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom

internal data class HnsWebSocketFrame(
    val fin: Boolean,
    val opcode: Int,
    val payload: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HnsWebSocketFrame) return false
        return fin == other.fin && opcode == other.opcode && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = fin.hashCode()
        result = 31 * result + opcode
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

internal class HnsWebSocketFrameParser(
    private val maxPayloadBytes: Int = MAX_PAYLOAD_BYTES,
    private val onFrame: (HnsWebSocketFrame) -> Unit,
) {
    private var buffer = ByteArray(0)

    @Throws(IOException::class)
    fun append(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size) {
        if (length <= 0) {
            return
        }
        if (offset < 0 || length < 0 || offset + length > bytes.size) {
            throw IOException("invalid frame buffer range")
        }
        val appended = ByteArray(buffer.size + length)
        buffer.copyInto(appended, 0)
        bytes.copyInto(appended, buffer.size, offset, offset + length)
        buffer = appended
        parseAvailableFrames()
    }

    @Throws(IOException::class)
    private fun parseAvailableFrames() {
        var cursor = 0
        while (true) {
            val available = buffer.size - cursor
            if (available < MIN_HEADER_BYTES) {
                break
            }

            val first = buffer[cursor].toInt() and 0xff
            val second = buffer[cursor + 1].toInt() and 0xff
            val fin = (first and FIN_BIT) != 0
            val opcode = first and OPCODE_MASK
            val masked = (second and MASK_BIT) != 0
            var payloadLength = (second and LENGTH_MASK).toLong()
            var headerLength = MIN_HEADER_BYTES

            if (payloadLength == LENGTH_16_MARKER.toLong()) {
                if (available < headerLength + SHORT_LENGTH_BYTES) {
                    break
                }
                payloadLength = unsignedShort(cursor + headerLength).toLong()
                headerLength += SHORT_LENGTH_BYTES
            } else if (payloadLength == LENGTH_64_MARKER.toLong()) {
                if (available < headerLength + LONG_LENGTH_BYTES) {
                    break
                }
                payloadLength = unsignedLong(cursor + headerLength)
                headerLength += LONG_LENGTH_BYTES
            }

            if (payloadLength < 0 || payloadLength > maxPayloadBytes) {
                throw IOException("websocket frame is too large")
            }
            if (masked) {
                headerLength += MASK_BYTES
            }
            val frameLength = headerLength + payloadLength.toInt()
            if (available < frameLength) {
                break
            }

            val payloadStart = cursor + headerLength
            val payload = buffer.copyOfRange(payloadStart, payloadStart + payloadLength.toInt())
            if (masked) {
                val maskStart = cursor + headerLength - MASK_BYTES
                for (index in payload.indices) {
                    payload[index] = (payload[index].toInt() xor buffer[maskStart + (index % MASK_BYTES)].toInt()).toByte()
                }
            }
            onFrame(HnsWebSocketFrame(fin, opcode, payload))
            cursor += frameLength
        }

        if (cursor > 0) {
            buffer = buffer.copyOfRange(cursor, buffer.size)
        }
    }

    private fun unsignedShort(offset: Int): Int =
        ((buffer[offset].toInt() and 0xff) shl 8) or (buffer[offset + 1].toInt() and 0xff)

    @Throws(IOException::class)
    private fun unsignedLong(offset: Int): Long {
        var value = 0L
        for (index in 0 until LONG_LENGTH_BYTES) {
            value = (value shl 8) or (buffer[offset + index].toLong() and 0xff)
        }
        if (value < 0) {
            throw IOException("websocket frame is too large")
        }
        return value
    }

    private companion object {
        const val MIN_HEADER_BYTES = 2
        const val SHORT_LENGTH_BYTES = 2
        const val LONG_LENGTH_BYTES = 8
        const val MASK_BYTES = 4
        const val FIN_BIT = 0x80
        const val MASK_BIT = 0x80
        const val OPCODE_MASK = 0x0f
        const val LENGTH_MASK = 0x7f
        const val LENGTH_16_MARKER = 126
        const val LENGTH_64_MARKER = 127
        const val MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
    }
}

internal object HnsWebSocketFrameCodec {
    const val OPCODE_CONTINUATION = 0x0
    const val OPCODE_TEXT = 0x1
    const val OPCODE_BINARY = 0x2
    const val OPCODE_CLOSE = 0x8
    const val OPCODE_PING = 0x9
    const val OPCODE_PONG = 0xA

    private val secureRandom = SecureRandom()

    fun encodeClientFrame(opcode: Int, payload: ByteArray): ByteArray {
        val mask = ByteArray(MASK_BYTES)
        secureRandom.nextBytes(mask)
        return encodeClientFrame(opcode, payload, mask)
    }

    internal fun encodeClientFrame(opcode: Int, payload: ByteArray, mask: ByteArray): ByteArray {
        require(mask.size == MASK_BYTES) { "mask must be 4 bytes" }
        val output = ByteArrayOutputStream()
        output.write(FIN_BIT or (opcode and OPCODE_MASK))
        writeLength(output, payload.size, masked = true)
        output.write(mask)
        payload.forEachIndexed { index, byte ->
            output.write(byte.toInt() xor mask[index % MASK_BYTES].toInt())
        }
        return output.toByteArray()
    }

    fun closePayload(code: Int, reason: String): ByteArray {
        val reasonBytes = reason.toByteArray(Charsets.UTF_8)
        val payload = ByteArray(STATUS_CODE_BYTES + reasonBytes.size)
        payload[0] = ((code ushr 8) and 0xff).toByte()
        payload[1] = (code and 0xff).toByte()
        reasonBytes.copyInto(payload, STATUS_CODE_BYTES)
        return payload
    }

    fun closeCode(payload: ByteArray): Int? {
        if (payload.size < STATUS_CODE_BYTES) {
            return null
        }
        return ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
    }

    fun closeReason(payload: ByteArray): String {
        if (payload.size <= STATUS_CODE_BYTES) {
            return ""
        }
        return payload.copyOfRange(STATUS_CODE_BYTES, payload.size).toString(Charsets.UTF_8)
    }

    private fun writeLength(output: ByteArrayOutputStream, length: Int, masked: Boolean) {
        val maskBit = if (masked) MASK_BIT else 0
        when {
            length < LENGTH_16_MARKER -> output.write(maskBit or length)
            length <= 0xffff -> {
                output.write(maskBit or LENGTH_16_MARKER)
                output.write((length ushr 8) and 0xff)
                output.write(length and 0xff)
            }
            else -> {
                output.write(maskBit or LENGTH_64_MARKER)
                for (shift in 56 downTo 0 step 8) {
                    output.write((length.toLong() ushr shift).toInt() and 0xff)
                }
            }
        }
    }

    private const val FIN_BIT = 0x80
    private const val MASK_BIT = 0x80
    private const val OPCODE_MASK = 0x0f
    private const val MASK_BYTES = 4
    private const val STATUS_CODE_BYTES = 2
    private const val LENGTH_16_MARKER = 126
    private const val LENGTH_64_MARKER = 127
}
