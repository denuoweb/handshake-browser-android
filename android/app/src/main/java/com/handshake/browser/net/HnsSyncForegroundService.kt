package com.handshake.browser.net

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.os.IBinder
import androidx.core.content.ContextCompat
import com.handshake.browser.R

class HnsSyncForegroundService : Service() {
    private var scheduler: HnsSyncScheduler? = null

    override fun onCreate() {
        super.onCreate()
        notificationManager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.sync_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }

        startForeground(
            NOTIFICATION_ID,
            buildNotification(null),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
        )
        ensureScheduler()
        return START_STICKY
    }

    override fun onDestroy() {
        scheduler?.close()
        scheduler = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureScheduler() {
        if (scheduler != null) {
            return
        }

        scheduler = HnsSyncScheduler(filesDir).also { newScheduler ->
            newScheduler.start { snapshot ->
                publishSnapshot(snapshot)
                updateNotification(snapshot)
            }
        }
    }

    private fun publishSnapshot(snapshot: HnsSyncSnapshot) {
        sendBroadcast(
            Intent(ACTION_SYNC_SNAPSHOT)
                .setPackage(packageName)
                .putExtra(EXTRA_STATUS_JSON, snapshot.statusJson)
                .putExtra(EXTRA_UPDATED_AT_MILLIS, snapshot.updatedAtMillis),
        )
    }

    private fun updateNotification(snapshot: HnsSyncSnapshot) {
        notificationManager.notify(NOTIFICATION_ID, buildNotification(snapshot))
    }

    private fun buildNotification(snapshot: HnsSyncSnapshot?): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(getString(R.string.sync_notification_title))
            .setContentText(notificationText(snapshot))
            .setOngoing(true)
            .setShowWhen(false)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                    getString(R.string.sync_notification_stop),
                    PendingIntent.getService(
                        this,
                        0,
                        Intent(this, HnsSyncForegroundService::class.java).setAction(ACTION_STOP),
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                    ),
                ).build(),
            )
            .build()

    private fun notificationText(snapshot: HnsSyncSnapshot?): String = when {
        snapshot == null -> getString(R.string.sync_notification_starting)
        else -> notificationText(HnsSyncProgress.fromJson(snapshot.statusJson))
    }

    private fun notificationText(progress: HnsSyncProgress): String = when {
        progress.status == "error" || progress.status == "seed_failed" -> {
            getString(R.string.sync_notification_error)
        }
        progress.isBehind || progress.status == "syncing" -> progress.summary()
        else -> getString(R.string.sync_notification_running)
    }

    private val notificationManager: NotificationManager
        get() = getSystemService(NotificationManager::class.java)

    companion object {
        const val ACTION_SYNC_SNAPSHOT = "com.handshake.browser.net.action.SYNC_SNAPSHOT"
        const val EXTRA_STATUS_JSON = "com.handshake.browser.net.extra.STATUS_JSON"
        const val EXTRA_UPDATED_AT_MILLIS = "com.handshake.browser.net.extra.UPDATED_AT_MILLIS"

        private const val ACTION_START = "com.handshake.browser.net.action.START_SYNC"
        private const val ACTION_STOP = "com.handshake.browser.net.action.STOP_SYNC"
        private const val CHANNEL_ID = "hns_sync"
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, HnsSyncForegroundService::class.java).setAction(ACTION_START),
            )
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, HnsSyncForegroundService::class.java))
        }
    }
}
