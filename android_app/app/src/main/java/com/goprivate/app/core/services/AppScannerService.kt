@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.core.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import com.goprivate.app.R
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicInteger

class AppScannerService : Service() {
    private val CHANNEL_ID = "goprivate_scanner_channel"
    private val ALERTS_CHANNEL_ID = "goprivate_alerts_channel"

    companion object {
        private const val TAG = "AppScannerService"
        private const val NOTIFICATION_ID = 9001
        private const val COMPLETION_NOTIFICATION_ID = 9002

        const val ACTION_START_BATCH_SCAN = "com.goprivate.app.action.START_BATCH_SCAN"
        const val ACTION_START_SINGLE_SCAN = "com.goprivate.app.action.START_SINGLE_SCAN"
        const val EXTRA_PACKAGE_NAME = "extra_package_name"
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    private val scanMutex = Mutex()
    private val activeJobsCount = AtomicInteger(0)

    private var lastNotificationTime = 0L
    private val diskCache by lazy { getSharedPreferences("goprivate_forensic_cache", MODE_PRIVATE) }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val stopRequested = intent?.getBooleanExtra("STOP_SCAN", false) ?: false

        if (stopRequested) {
            Log.d(TAG, "🛑 Scan aborted by user.")
            serviceScope.cancel()
            cleanupAndStop()
            return START_NOT_STICKY
        }

        Log.d(TAG, "🚀 Scanner Service Booting...")

        try {
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "GoPrivate::ScannerWakeLock")
            wakeLock?.acquire(15 * 60 * 1000L)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to acquire WakeLock", e)
        }

        val initialNotification = buildNotification("Initializing System Audit...", 0, 100)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, initialNotification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, initialNotification)
        }

        val action = intent?.action
        val targetPackage = intent?.getStringExtra(EXTRA_PACKAGE_NAME)

        activeJobsCount.incrementAndGet()

        serviceScope.launch {
            scanMutex.withLock {
                try {
                    if (action == ACTION_START_SINGLE_SCAN && targetPackage != null) {
                        executeSingleAppScan(targetPackage)
                    } else if (action == ACTION_START_BATCH_SCAN) {
                        executeFullSystemScan()
                    }
                } finally {
                    if (activeJobsCount.decrementAndGet() == 0) {
                        cleanupAndStop()
                    }
                }
            }
        }

        return START_STICKY
    }

    private suspend fun executeSingleAppScan(targetPackage: String) {
        try {
            if (!EngineBStaticManager.isReady()) {
                EngineBStaticManager.initialize(applicationContext)
            }

            val appName = try {
                packageManager.getApplicationInfo(targetPackage, 0).loadLabel(packageManager).toString()
            } catch (e: Exception) { targetPackage }

            updateNotification("Auditing: $appName", 50, 100)

            val startIntent = Intent("com.goprivate.app.SCAN_PROGRESS").apply {
                putExtra("isScanning", true)
                putExtra("progress", 50)
                putExtra("totalApps", 1)
                putExtra("scannedApps", 0)
            }
            sendBroadcast(startIntent)

            // 🚨 LET ENGINE B DO ITS JOB
            var (riskScore, forensicReport) = EngineBStaticManager.analyzeApp(targetPackage, applicationContext)

            // 🚨 THE TRANSPARENCY OVERRIDE: If it's our app, clamp the risk to 0.0 but KEEP the XAI report!
            if (targetPackage == packageName) {
                Log.d(TAG, "🛡️ GoPrivate Core scanned. Clamping ML risk score to safe, preserving XAI forensics.")
                riskScore = 0.0f
            }

            if (riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD) {
                TelemetryManager.logThreatBlocked(appName, "Static App Analysis", riskScore)
                ThreatRepository.addThreat(appName, targetPackage, "Malicious API Signature", riskScore)
            }

            val featureString = forensicReport.joinToString(";;;")
            val serializedData = "$riskScore|${System.currentTimeMillis()}|false|$featureString"

            diskCache.edit(commit = false) { putString(targetPackage, serializedData) }

            // 🚨 UI DESYNC FIXED: Broadcasts now fire unconditionally
            val resultIntent = Intent("com.goprivate.app.APP_SCANNED_RESULT").apply {
                putExtra("packageName", targetPackage)
                putExtra("riskScore", riskScore)
            }
            sendBroadcast(resultIntent)

            val finishIntent = Intent("com.goprivate.app.SCAN_PROGRESS").apply {
                putExtra("isScanning", false)
                putExtra("progress", 100)
                putExtra("scannedApps", 1)
                putExtra("totalApps", 1)
            }
            sendBroadcast(finishIntent)

            if (riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD) {
                showCompletionNotification(1, 1)
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Fatal error in single scanner service", e)
        }
    }

    private suspend fun executeFullSystemScan() {
        try {
            if (!EngineBStaticManager.isReady()) {
                EngineBStaticManager.initialize(applicationContext)
            }

            val pm = packageManager
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }

            val targetApps = packages.filter { pkg ->
                pm.getLaunchIntentForPackage(pkg.packageName) != null
            }

            val totalApps = targetApps.size
            var scannedCount = 0
            var threatsFound = 0

            for (pkg in targetApps) {
                if (!serviceScope.isActive) {
                    Log.w(TAG, "⚠️ Scan cleanly aborted by OS/User.")
                    break
                }

                val appName = pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName

                val now = System.currentTimeMillis()
                if (now - lastNotificationTime > 500) {
                    updateNotification("Auditing: $appName", scannedCount, totalApps)
                    lastNotificationTime = now
                }

                try {
                    // 🚨 LET ENGINE B DO ITS JOB
                    var (riskScore, forensicReport) = EngineBStaticManager.analyzeApp(pkg.packageName, applicationContext)

                    // 🚨 THE TRANSPARENCY OVERRIDE
                    if (pkg.packageName == packageName) {
                        riskScore = 0.0f
                    }

                    if (riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD) {
                        threatsFound++
                        TelemetryManager.logThreatBlocked(appName, "Batch Static Scan", riskScore)
                        ThreatRepository.addThreat(appName, pkg.packageName, "Malicious API Signature", riskScore)
                    }

                    val featureString = forensicReport.joinToString(";;;")
                    val existingData = diskCache.getString(pkg.packageName, null)
                    val isIsolated = existingData?.split("|")?.getOrNull(2)?.toBooleanStrictOrNull() ?: false

                    val serializedData = "$riskScore|${System.currentTimeMillis()}|$isIsolated|$featureString"

                    diskCache.edit(commit = false) { putString(pkg.packageName, serializedData) }

                    // 🚨 UI DESYNC FIXED
                    val resultIntent = Intent("com.goprivate.app.APP_SCANNED_RESULT").apply {
                        putExtra("packageName", pkg.packageName)
                        putExtra("riskScore", riskScore)
                    }
                    sendBroadcast(resultIntent)

                } catch (e: Exception) {
                    Log.e(TAG, "⚠️ Skipping ${pkg.packageName} due to extraction failure", e)
                }

                scannedCount++

                val progressIntent = Intent("com.goprivate.app.SCAN_PROGRESS").apply {
                    putExtra("progress", ((scannedCount.toFloat() / totalApps) * 100).toInt())
                    putExtra("scannedApps", scannedCount)
                    putExtra("totalApps", totalApps)
                    putExtra("threatsFound", threatsFound)
                    putExtra("isScanning", true)
                }
                sendBroadcast(progressIntent)

                delay(150)
            }

            val finishIntent = Intent("com.goprivate.app.SCAN_PROGRESS").apply {
                putExtra("isScanning", false)
                putExtra("progress", 100)
                putExtra("scannedApps", scannedCount)
                putExtra("totalApps", totalApps)
                putExtra("threatsFound", threatsFound)
            }
            sendBroadcast(finishIntent)

            showCompletionNotification(scannedCount, threatsFound)

        } catch (e: Exception) {
            Log.e(TAG, "❌ Fatal error in scanner service", e)
        }
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager

        val progressChannel = NotificationChannel(
            CHANNEL_ID, "Background System Scanner", NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Shows progress of full system malware audits." }

        val alertsChannel = NotificationChannel(
            ALERTS_CHANNEL_ID, "Threat Alerts & Updates", NotificationManager.IMPORTANCE_HIGH
        ).apply { description = "High priority threat detections and scan completions." }

        manager.createNotificationChannels(listOf(progressChannel, alertsChannel))
    }

    private fun showCompletionNotification(scanned: Int, threats: Int) {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val title = if (threats > 0) "🚨 Threats Detected" else "✅ Audit Complete"
        val text = if (threats > 0) "Found $threats threats in $scanned apps. Tap to review." else "All $scanned endpoint modules are safe."

        val notification = NotificationCompat.Builder(this, ALERTS_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(getLaunchPendingIntent())
            .setAutoCancel(true)
            .setColor(ContextCompat.getColor(this, if (threats > 0) R.color.alert_red_primary else R.color.neon_green_primary))
            .build()

        manager.notify(COMPLETION_NOTIFICATION_ID, notification)
    }

    private fun getLaunchPendingIntent(): PendingIntent? {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return launchIntent?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        }
    }

    private fun buildNotification(text: String, progress: Int, max: Int): Notification {
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("GoPrivate Endpoint Audit")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setProgress(max, progress, false)
            .setOngoing(true)
            .setColor(ContextCompat.getColor(this, R.color.neon_cyan_primary))

        getLaunchPendingIntent()?.let { builder.setContentIntent(it) }

        return builder.build()
    }

    private fun updateNotification(text: String, progress: Int, max: Int) {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text, progress, max))
    }

    private fun cleanupAndStop() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
                Log.d(TAG, "🔓 CPU WakeLock Released.")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing WakeLock", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        cleanupAndStop()
        Log.d(TAG, "🛑 Scanner Service Destroyed.")
    }
}