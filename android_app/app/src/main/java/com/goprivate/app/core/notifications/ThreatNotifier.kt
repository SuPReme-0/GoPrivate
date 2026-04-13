package com.goprivate.app.core.notifications

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.goprivate.app.MainActivity
import com.goprivate.app.R

/**
 * Handles all high-priority system alerts.
 * Uses a dedicated channel to bypass standard notification grouping.
 */
object ThreatNotifier {

    private const val CHANNEL_ID = "goprivate_threat_alerts"
    private const val CHANNEL_NAME = "Critical Threat Alerts"
    private const val NOTIFICATION_ID_BASE = 9000

    private fun createChannel(context: Context) {
        // 🚨 LINT FIX: SDK check removed because app minimum is API 26+
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_HIGH // 🚨 Forces heads-up popup and max vibration
        ).apply {
            description = "Alerts for detected malware and network intrusions."
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 500, 200, 500)
        }

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(channel)
    }

    /**
     * Fires a critical heads-up notification prompting the user to uninstall malware.
     */
    fun showActionableMalwareAlert(context: Context, appName: String, message: String, actionIntent: PendingIntent) {
        // 🚨 SILENT FAILURE FIX: Guarantee the channel exists before attempting to notify
        createChannel(context)

        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // 🚨 CHANNEL ID FIX: Use the constant, not a hardcoded mistyped string
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle("🚨 Threat Detected: $appName")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setColor(ContextCompat.getColor(context, R.color.alert_red_primary))
            .setAutoCancel(true)
            .setContentIntent(actionIntent) // Tapping the notification opens the uninstaller!
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .build()

        notificationManager.notify(appName.hashCode(), notification)
    }

    fun showMalwareAlert(context: Context, appName: String, packageName: String) {
        createChannel(context)

        // 1. Main Intent: Opens the App Dashboard
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context,
            packageName.hashCode(),
            mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // 2. 🚨 THE PRODUCTION UPGRADE: Directly Uninstall Action Button
        val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
            // 🚨 LINT FIX: Using modern KTX toUri() extension
            data = "package:$packageName".toUri()
        }
        val uninstallPendingIntent = PendingIntent.getActivity(
            context,
            packageName.hashCode() + 1,
            uninstallIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🚨 MALWARE DETECTED: $appName")
            .setContentText("A malicious module ($packageName) was installed. Purge immediately.")
            .setPriority(NotificationCompat.PRIORITY_MAX) // Force popup over other apps
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC) // 🚨 Show on the lock screen
            .setColor(ContextCompat.getColor(context, R.color.alert_red_primary)) // 🚨 LINT FIX: ContextCompat imported
            .setContentIntent(mainPendingIntent)
            .addAction(
                android.R.drawable.ic_delete,
                "UNINSTALL NOW", // 🚨 Allows user to uninstall directly from the notification
                uninstallPendingIntent
            )
            .setAutoCancel(true)
            .build()

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID_BASE + packageName.hashCode(), notification)
    }
}