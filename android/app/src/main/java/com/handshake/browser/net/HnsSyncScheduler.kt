package com.handshake.browser.net

import java.io.Closeable
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

data class HnsSyncSnapshot(
    val statusJson: String,
    val updatedAtMillis: Long,
)

class HnsSyncScheduler(
    private val dataDir: File,
    private val bridge: HnsSyncBridge = NativeBridge,
    private val idleIntervalMs: Long = DEFAULT_IDLE_INTERVAL_MS,
    private val activeIntervalMs: Long = DEFAULT_ACTIVE_INTERVAL_MS,
    private val retryIntervalMs: Long = DEFAULT_RETRY_INTERVAL_MS,
    private val executor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(),
    private val clock: () -> Long = System::currentTimeMillis,
) : Closeable {
    private val running = AtomicBoolean(false)
    private var future: ScheduledFuture<*>? = null

    @Volatile
    var lastSnapshot: HnsSyncSnapshot? = null
        private set

    fun start(onSnapshot: (HnsSyncSnapshot) -> Unit) {
        if (!running.compareAndSet(false, true)) {
            return
        }

        scheduleNext(0, onSnapshot)
    }

    internal fun tick(onSnapshot: (HnsSyncSnapshot) -> Unit) {
        if (!running.get()) {
            return
        }

        val snapshot = runOnce(onSnapshot)
        if (running.get()) {
            scheduleNext(nextDelayMs(snapshot), onSnapshot)
        }
    }

    internal fun runOnce(onSnapshot: (HnsSyncSnapshot) -> Unit): HnsSyncSnapshot {
        val snapshot = HnsSyncSnapshot(
            statusJson = bridge.syncOnce(dataDir.absolutePath),
            updatedAtMillis = clock(),
        )
        lastSnapshot = snapshot
        onSnapshot(snapshot)
        return snapshot
    }

    internal fun nextDelayMs(snapshot: HnsSyncSnapshot): Long {
        val progress = HnsSyncProgress.fromJson(snapshot.statusJson)
        return when {
            progress.shouldRetrySoon -> retryIntervalMs
            progress.shouldContinueSoon -> activeIntervalMs
            else -> idleIntervalMs
        }
    }

    private fun scheduleNext(delayMs: Long, onSnapshot: (HnsSyncSnapshot) -> Unit) {
        future = executor.schedule(
            { tick(onSnapshot) },
            delayMs,
            TimeUnit.MILLISECONDS,
        )
    }

    override fun close() {
        running.set(false)
        future?.cancel(true)
        executor.shutdownNow()
    }

    companion object {
        const val DEFAULT_ACTIVE_INTERVAL_MS: Long = 1_000
        const val DEFAULT_RETRY_INTERVAL_MS: Long = 10_000
        const val DEFAULT_IDLE_INTERVAL_MS: Long = 10 * 60 * 1_000
    }
}
