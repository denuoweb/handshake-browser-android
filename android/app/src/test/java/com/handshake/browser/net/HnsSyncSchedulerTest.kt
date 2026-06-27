package com.handshake.browser.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import java.io.File

class HnsSyncSchedulerTest {
    @Test
    fun runOncePublishesNativeSyncSnapshot() {
        val dataDir = File("/tmp/hns-browser-test")
        val bridge = RecordingSyncBridge(
            """{"status":"idle","attempted":0,"successful":0,"accepted":0,"peerCount":0,"peerGroups":0,"bestHeight":0,"bestPeerHeight":null,"resourceCacheEntries":0,"resourceCacheBytes":0,"resourceCacheEvicted":0,"error":null}""",
        )
        val scheduler = HnsSyncScheduler(
            dataDir = dataDir,
            bridge = bridge,
            clock = { 1234L },
        )
        var snapshot: HnsSyncSnapshot? = null

        scheduler.runOnce { snapshot = it }

        assertEquals(dataDir.absolutePath, bridge.paths.single())
        assertEquals(1234L, snapshot?.updatedAtMillis)
        assertEquals(bridge.response, snapshot?.statusJson)
        assertSame(snapshot, scheduler.lastSnapshot)
        scheduler.close()
    }

    @Test
    fun nextDelayUsesActiveIntervalWhilePeerHeightIsAhead() {
        val scheduler = HnsSyncScheduler(
            dataDir = File("/tmp/hns-browser-test"),
            bridge = RecordingSyncBridge("{}"),
            activeIntervalMs = 7L,
            retryIntervalMs = 11L,
            idleIntervalMs = 13L,
        )

        assertEquals(
            7L,
            scheduler.nextDelayMs(
                HnsSyncSnapshot(
                    statusJson = """{"status":"synced","bestHeight":45000,"bestPeerHeight":335684}""",
                    updatedAtMillis = 1L,
                ),
            ),
        )
        assertEquals(
            13L,
            scheduler.nextDelayMs(
                HnsSyncSnapshot(
                    statusJson = """{"status":"up_to_date","bestHeight":335684,"bestPeerHeight":335684}""",
                    updatedAtMillis = 2L,
                ),
            ),
        )
        assertEquals(
            7L,
            scheduler.nextDelayMs(
                HnsSyncSnapshot(
                    statusJson = """{"status":"syncing","bestHeight":92000,"bestPeerHeight":null,"estimatedTipHeight":335684,"peerCount":0}""",
                    updatedAtMillis = 3L,
                ),
            ),
        )
        assertEquals(
            11L,
            scheduler.nextDelayMs(
                HnsSyncSnapshot(
                    statusJson = """{"status":"peer_failed","bestHeight":45000,"bestPeerHeight":335684}""",
                    updatedAtMillis = 4L,
                ),
            ),
        )
        assertEquals(
            11L,
            scheduler.nextDelayMs(
                HnsSyncSnapshot(
                    statusJson = """{"status":"idle","bestHeight":null,"bestPeerHeight":null,"estimatedTipHeight":335684,"peerCount":0}""",
                    updatedAtMillis = 5L,
                ),
            ),
        )
        scheduler.close()
    }

    private class RecordingSyncBridge(
        val response: String,
    ) : HnsSyncBridge {
        val paths = mutableListOf<String>()

        override fun syncOnce(dataDir: String): String {
            paths += dataDir
            return response
        }
    }
}
