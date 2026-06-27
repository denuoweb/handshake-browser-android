package com.handshake.browser.net

import java.text.NumberFormat
import java.util.Locale

data class HnsSyncProgress(
    val status: String,
    val bestHeight: Long?,
    val bestPeerHeight: Long?,
    val attempted: Long?,
    val successful: Long?,
    val accepted: Long?,
    val failed: Long?,
    val peerCount: Long?,
    val peerGroups: Long?,
    val estimatedTipHeight: Long?,
) {
    val targetHeight: Long?
        get() = bestPeerHeight ?: estimatedTipHeight

    val isBehind: Boolean
        get() {
            val best = bestHeight ?: return false
            val target = targetHeight ?: return false
            return target > best
        }

    val shouldContinueSoon: Boolean
        get() = isBehind || hasUnknownTargetProgress || status in ACTIVE_STATUSES

    val shouldRetrySoon: Boolean
        get() = status in RETRY_STATUSES || needsPeerDiscovery

    val hasUnknownTargetProgress: Boolean
        get() = bestHeight != null && bestHeight > 0L && bestPeerHeight == null

    val needsPeerDiscovery: Boolean
        get() = status == "idle" && (peerCount ?: 0L) == 0L

    fun progressPermille(): Int? {
        val best = bestHeight ?: return null
        val target = targetHeight ?: return null
        if (target <= 0L) return null
        return ((best.coerceIn(0L, target) * 1000L) / target).toInt()
    }

    fun summary(): String {
        val formattedBest = bestHeight?.formatHeight() ?: "unknown"
        val target = targetHeight
        val targetPart = when {
            isBehind && target != null -> "target ${target.formatHeight()}"
            bestPeerHeight != null -> "bestPeerHeight ${bestPeerHeight.formatHeight()}"
            estimatedTipHeight != null -> "target ${estimatedTipHeight.formatHeight()}"
            else -> "target unknown"
        }
        val acceptedPart = accepted
            ?.takeIf { it > 0L }
            ?.let { " • accepted +${it.formatHeight()}" }
            .orEmpty()
        val peerPart = peerCount
            ?.takeIf { it > 0L }
            ?.let { " • peers ${it.formatHeight()}" }
            .orEmpty()
        return "${status.ifBlank { "idle" }} • bestHeight $formattedBest • $targetPart$acceptedPart$peerPart"
    }

    private fun Long.formatHeight(): String =
        NumberFormat.getIntegerInstance(Locale.US).format(this)

    companion object {
        private val ACTIVE_STATUSES = setOf("syncing", "synced", "attempted")
        private val RETRY_STATUSES = setOf("error", "peer_failed", "seed_failed")

        fun fromJson(statusJson: String?): HnsSyncProgress {
            if (statusJson.isNullOrBlank()) {
                return HnsSyncProgress(
                    status = "idle",
                    bestHeight = null,
                    bestPeerHeight = null,
                    attempted = null,
                    successful = null,
                    accepted = null,
                    failed = null,
                    peerCount = null,
                    peerGroups = null,
                    estimatedTipHeight = null,
                )
            }
            return HnsSyncProgress(
                status = stringField(statusJson, "status") ?: "idle",
                bestHeight = longField(statusJson, "bestHeight"),
                bestPeerHeight = longField(statusJson, "bestPeerHeight"),
                attempted = longField(statusJson, "attempted"),
                successful = longField(statusJson, "successful"),
                accepted = longField(statusJson, "accepted"),
                failed = longField(statusJson, "failed"),
                peerCount = longField(statusJson, "peerCount"),
                peerGroups = longField(statusJson, "peerGroups"),
                estimatedTipHeight = longField(statusJson, "estimatedTipHeight"),
            )
        }

        private fun stringField(json: String, name: String): String? {
            val pattern = """"$name"\s*:\s*"([^"]*)"""".toRegex()
            return pattern.find(json)?.groupValues?.getOrNull(1)
        }

        private fun longField(json: String, name: String): Long? {
            val pattern = """"$name"\s*:\s*(null|-?\d+)""".toRegex()
            val value = pattern.find(json)?.groupValues?.getOrNull(1) ?: return null
            return value.takeUnless { it == "null" }?.toLongOrNull()
        }
    }
}
