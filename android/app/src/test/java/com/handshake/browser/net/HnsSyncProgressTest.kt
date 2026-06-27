package com.handshake.browser.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsSyncProgressTest {
    @Test
    fun parsesHeightsAndReportsBehindProgress() {
        val progress = HnsSyncProgress.fromJson(
            """{"status":"syncing","attempted":4,"successful":1,"accepted":2000,"failed":3,"peerCount":4,"peerGroups":4,"bestHeight":93344,"bestPeerHeight":335684,"estimatedTipHeight":335900}""",
        )

        assertEquals("syncing", progress.status)
        assertEquals(93_344L, progress.bestHeight)
        assertEquals(335_684L, progress.bestPeerHeight)
        assertEquals(2_000L, progress.accepted)
        assertTrue(progress.isBehind)
        assertTrue(progress.shouldContinueSoon)
        assertEquals(278, progress.progressPermille())
        assertEquals(
            "syncing • bestHeight 93,344 • target 335,684 • accepted +2,000 • peers 4",
            progress.summary(),
        )
    }

    @Test
    fun upToDateProgressUsesIdlePolling() {
        val progress = HnsSyncProgress.fromJson(
            """{"status":"up_to_date","bestHeight":335684,"bestPeerHeight":335684}""",
        )

        assertFalse(progress.isBehind)
        assertFalse(progress.shouldContinueSoon)
        assertEquals(1000, progress.progressPermille())
    }

    @Test
    fun estimatedTipDrivesProgressWhenPeerHeightIsUnknown() {
        val progress = HnsSyncProgress.fromJson(
            """{"status":"syncing","bestHeight":92000,"bestPeerHeight":null,"estimatedTipHeight":335684,"peerCount":0}""",
        )

        assertTrue(progress.isBehind)
        assertTrue(progress.hasUnknownTargetProgress)
        assertTrue(progress.shouldContinueSoon)
        assertEquals(274, progress.progressPermille())
        assertEquals(
            "syncing • bestHeight 92,000 • target 335,684",
            progress.summary(),
        )
    }

    @Test
    fun idleWithoutPeersRetriesDiscovery() {
        val progress = HnsSyncProgress.fromJson(
            """{"status":"idle","bestHeight":null,"bestPeerHeight":null,"estimatedTipHeight":335684,"peerCount":0}""",
        )

        assertTrue(progress.shouldRetrySoon)
    }
}
