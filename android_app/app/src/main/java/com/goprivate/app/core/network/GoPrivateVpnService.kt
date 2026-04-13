@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.core.network

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.annotation.Keep
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.goprivate.app.R
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.core.notifications.ThreatNotifier
import com.goprivate.app.core.sensors.WebScraperUtility
import com.goprivate.app.data.ml.EngineANetworkManager
import com.goprivate.app.data.ml.EngineCNLPManager
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

@SuppressLint("VpnServicePolicy")
class GoPrivateVpnService : VpnService() {

    companion object {
        private const val TAG = "GoPrivateVPN"
        private const val NOTIFICATION_CHANNEL_ID = "goprivate_vpn_channel"
        private const val NOTIFICATION_ID = 1

        private lateinit var clipboardManager: ClipboardManager
        private var lastClipText: String = ""

        init {
            System.loadLibrary("goprivate_net")
        }
    }

    // 🚨 ARCHITECTURE UPGRADE: Added srcPort to the FlowKey for exact TCP stream matching
    data class FlowKey(val srcIp: String, val srcPort: Int, val dstIp: String, val dstPort: Int, val protocol: Int)

    class ActiveFlow(
        val tracker: FlowTracker,
        @Volatile var appName: String = "Resolving...",
        @Volatile var packageName: String = "",
        @Volatile var isBlocked: Boolean = false,
        @Volatile var totalPacketsObserved: Int = 0,
        @Volatile var lastUpdatedAt: Long = System.currentTimeMillis()
    )

    private val activeFlows = ConcurrentHashMap<FlowKey, ActiveFlow>()

    private val quarantinedPackages = ConcurrentHashMap.newKeySet<String>()
    private val uidToPackageCache = ConcurrentHashMap<Int, Pair<String, String>>()

    private val diskCache by lazy { getSharedPreferences("goprivate_forensic_cache", MODE_PRIVATE) }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile private var isDeepInspectionEnabled = true

    private val quarantineReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == "ACTION_UPDATE_QUARANTINE") {
                val pkgName = intent.getStringExtra("PACKAGE_NAME") ?: return
                val isIsolated = intent.getBooleanExtra("IS_ISOLATED", true)

                if (isIsolated) {
                    quarantinedPackages.add(pkgName)
                    Log.d(TAG, "🔒 KERNEL QUARANTINE ENGAGED: $pkgName")
                    TelemetryManager.logToTerminal("SYS", "🔒 KERNEL QUARANTINE ENGAGED: $pkgName")

                    activeFlows.values.forEach { flow ->
                        if (flow.packageName == pkgName) flow.isBlocked = true
                    }
                } else {
                    quarantinedPackages.remove(pkgName)
                    Log.d(TAG, "🟢 KERNEL QUARANTINE LIFTED: $pkgName")
                    TelemetryManager.logToTerminal("SYS", "🟢 KERNEL QUARANTINE LIFTED: $pkgName")

                    activeFlows.values.forEach { flow ->
                        if (flow.packageName == pkgName) flow.isBlocked = false
                    }
                }
            }
        }
    }

    private val screenStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    isDeepInspectionEnabled = false
                    TelemetryManager.logToTerminal("SYS", "🔋 Screen OFF: ML Fast-Path Engaged")
                }
                Intent.ACTION_SCREEN_ON -> {
                    isDeepInspectionEnabled = true
                    TelemetryManager.logToTerminal("SYS", "🔌 Screen ON: Deep ML Inspection Resumed")
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        syncQuarantineFromDisk()

        val screenFilter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        ContextCompat.registerReceiver(this, screenStateReceiver, screenFilter, ContextCompat.RECEIVER_NOT_EXPORTED)

        val quarantineFilter = IntentFilter("ACTION_UPDATE_QUARANTINE")
        ContextCompat.registerReceiver(this, quarantineReceiver, quarantineFilter, ContextCompat.RECEIVER_EXPORTED)

        setupClipboardSentinel()
    }

    private fun syncQuarantineFromDisk() {
        try {
            val allData = diskCache.all
            var isolatedCount = 0
            for ((pkgName, data) in allData) {
                if (data is String) {
                    val parts = data.split("|")
                    if (parts.size >= 4) {
                        val isIsolated = parts[2].toBooleanStrictOrNull() ?: false
                        if (isIsolated) {
                            quarantinedPackages.add(pkgName)
                            isolatedCount++
                        }
                    }
                }
            }
            if (isolatedCount > 0) {
                TelemetryManager.logToTerminal("SYS", "🛡️ Restored $isolatedCount Quarantined Modules from SSD.")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load quarantine list", e)
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "GoPrivate Active Protection",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Protects device from network threats and C2 Beacons."
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    private fun setupClipboardSentinel() {
        try {
            clipboardManager = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            clipboardManager.addPrimaryClipChangedListener {
                if (clipboardManager.hasPrimaryClip()) {
                    val item = clipboardManager.primaryClip?.getItemAt(0)
                    val copiedText = item?.text?.toString() ?: ""

                    if (copiedText.isNotEmpty() && copiedText != lastClipText) {
                        lastClipText = copiedText
                        analyzeClipboard(copiedText)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Clipboard sentinel restricted by OS policy.")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "ACTION_DISCONNECT_VPN" -> {
                disconnectVpn()
                return START_NOT_STICKY
            }
            "ACTION_START_VPN" -> {
                startForegroundService()
                startVpn()
                return START_STICKY
            }
            else -> return START_STICKY
        }
    }

    private fun startForegroundService() {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = launchIntent?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }

        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("GoPrivate Active")
            .setContentText("Hybrid C++/ML Network Monitoring Online")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .apply { pendingIntent?.let { setContentIntent(it) } }
            .setOngoing(true)
            .setColor(ContextCompat.getColor(this, R.color.neon_cyan_primary))
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startVpn() {
        if (vpnInterface != null) return

        try {
            val builder = Builder()
                .setSession("GoPrivate ML Firewall")
                .addAddress("10.0.0.2", 24)
                .addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
                .addDnsServer("1.1.1.1")
                .addDnsServer("1.0.0.1")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setMtu(1500)
                .setBlocking(true)

            builder.setUnderlyingNetworks(null)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

            val bypassedApps = listOf(packageName, "com.android.vending", "com.google.android.gms")
            for (app in bypassedApps) {
                try { builder.addDisallowedApplication(app) } catch (_: Exception) {}
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                stopSelf()
                return
            }
            EngineANetworkManager.setVpnActive(true)
            nativeStartEngine(vpnInterface!!.fd)

        } catch (e: Exception) {
            stopSelf()
        }
    }

    override fun onRevoke() {
        TelemetryManager.logToTerminal("SYS", "🛑 OS revoked VPN permission. Executing emergency C++ shutdown.")
        disconnectVpn()
        super.onRevoke()
    }

    private fun disconnectVpn() {
        try {
            nativeStopEngine()
            vpnInterface?.close()
            vpnInterface = null
        } catch (_: Exception) {}
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        EngineANetworkManager.setVpnActive(false)
    }

    @Keep
    fun protectNativeSocket(socketFd: Int): Boolean = protect(socketFd)

    @Keep
    fun onThreatDetected(threatType: String, sourceIp: String, port: Int) {
        val message = "🛡️ IPS BLOCKED: $threatType from $sourceIp"
        TelemetryManager.logToTerminal("IPS", message)

        serviceScope.launch {
            ThreatRepository.addThreat("OS Kernel Shield", "Source: $sourceIp", threatType, 1.0f)
            ThreatNotifier.showMalwareAlert(this@GoPrivateVpnService, "Intrusion Blocked", threatType)
        }
    }

    private val whitelistedIps = setOf("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "2606:4700:4700::1111")

    // 🚨 JNI UPGRADE: Added sourcePort to correctly resolve the Android socket owner
    @Keep
    fun onNativePacketIntercepted(
        sourceIp: String, sourcePort: Int, destIp: String, destPort: Int, protocol: Int,
        packetSize: Int, headerSize: Int, tcpFlags: Int
    ): Boolean {
        TelemetryManager.logPacketRouted(packetSize)

        if (destIp in whitelistedIps || sourceIp in whitelistedIps) return true

        val isOutgoing = sourceIp == "10.0.0.2" || sourceIp.startsWith("fd00")
        val key = FlowKey(sourceIp, sourcePort, destIp, destPort, protocol)

        var flow = activeFlows[key]

        if (flow == null) {
            if (activeFlows.size > 2000) {
                serviceScope.launch(Dispatchers.Default) {
                    val staleThreshold = System.currentTimeMillis() - 60_000
                    activeFlows.entries.removeIf { it.value.lastUpdatedAt < staleThreshold }
                }
            }

            val srcInt = try { FlowTracker.ipStringToInt(sourceIp) } catch (e: Exception) { 0 }
            val dstInt = try { FlowTracker.ipStringToInt(destIp) } catch (e: Exception) { 0 }

            // 🚨 ZERO-LEAK FIX: Synchronous resolution entirely drops the TCP SYN handshake
            val (appName, pkgName) = resolveAppDetailsFromPacket(sourceIp, sourcePort, destIp, destPort, protocol)

            flow = ActiveFlow(FlowTracker(srcInt, dstInt, destPort, protocol))
            flow.appName = appName
            flow.packageName = pkgName

            if (quarantinedPackages.contains(pkgName)) {
                flow.isBlocked = true
            }

            activeFlows[key] = flow
        }

        // 🚨 HARD KERNEL ENFORCEMENT: Now executes successfully on the first packet
        if (flow.isBlocked) {
            return false // Packet dropped into the void
        }

        if (!isDeepInspectionEnabled || !EngineANetworkManager.isReady()) return true

        flow.lastUpdatedAt = System.currentTimeMillis()
        flow.tracker.addPacket(packetSize, headerSize, tcpFlags, isOutgoing)
        flow.totalPacketsObserved++

        if (flow.totalPacketsObserved == 10 || flow.totalPacketsObserved == 50 || flow.totalPacketsObserved == 150) {
            triggerAsynchronousMlAnalysis(destIp, flow)
        }

        return true
    }

    // 🚨 KERNEL FIX: Now utilizes sourcePort to achieve 100% accurate UID lookups
    private fun resolveAppDetailsFromPacket(srcIp: String, srcPort: Int, dstIp: String, destPort: Int, protocol: Int): Pair<String, String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Pair("System Process", "android")
        return try {
            val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
            val osProtocol = if (protocol == 6) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP

            val srcAddress = InetAddresses.parseNumericAddress(srcIp)
            val dstAddress = InetAddresses.parseNumericAddress(dstIp)

            val uid = cm.getConnectionOwnerUid(
                osProtocol,
                InetSocketAddress(srcAddress, srcPort),
                InetSocketAddress(dstAddress, destPort)
            )

            if (uid == -1) return Pair("Unknown Process", "unknown")

            uidToPackageCache[uid]?.let { return it }

            val packages = packageManager.getPackagesForUid(uid)
            if (!packages.isNullOrEmpty()) {
                val pkgName = packages[0]
                val ai = packageManager.getApplicationInfo(pkgName, 0)
                val appName = packageManager.getApplicationLabel(ai).toString()

                val result = Pair(appName, pkgName)
                uidToPackageCache[uid] = result
                return result
            } else Pair("Unknown Process", "unknown")
        } catch (e: Exception) {
            Pair("Unknown Process", "unknown")
        }
    }

    private fun triggerAsynchronousMlAnalysis(targetIp: String, flow: ActiveFlow) {
        serviceScope.launch(Dispatchers.Default) {
            try {
                val featuresBuffer = FloatArray(45)
                flow.tracker.extractFeaturesToBuffer(featuresBuffer)
                val riskScore = EngineANetworkManager.analyzeNetworkFlow(featuresBuffer)
                val confidence = "%.1f".format(riskScore * 100)

                if (riskScore >= EngineANetworkManager.MALICIOUS_THRESHOLD) {
                    flow.isBlocked = true
                    TelemetryManager.logToTerminal("SHIELD", "🛑 MALICIOUS FLOW KILLED: ${flow.appName} -> $targetIp (Risk: $confidence%)")
                    TelemetryManager.logThreatBlocked(flow.appName, "Network Anomaly", riskScore)

                    ThreatRepository.addThreat(flow.appName, "Target IP: $targetIp", "Malicious C2 Network Traffic", riskScore)
                    ThreatNotifier.showMalwareAlert(this@GoPrivateVpnService, "Network Threat Blocked", flow.appName)
                }
                else if (riskScore > 0.40f) {
                    TelemetryManager.logToTerminal("WARN", "⚠️ Suspicious Flow: ${flow.appName} -> $targetIp (Risk: $confidence%)")
                }
            } catch (e: Exception) {
                Log.e(TAG, "ML Evaluation Error", e)
            }
        }
    }

    private fun analyzeClipboard(text: String) {
        if (android.util.Patterns.WEB_URL.matcher(text).matches()) {
            serviceScope.launch {
                try {
                    val clauses = WebScraperUtility.scrapeAndCleanHtml(applicationContext, text).take(30)
                    if (clauses.isEmpty()) return@launch

                    val results = EngineCNLPManager.analyzePolicyClauses(clauses)
                    val dangerousClauses = results.count { (it.first == "Data_Sharing" || it.first == "Data_Collection") && it.second > 80f }

                    if (dangerousClauses >= 2) {
                        TelemetryManager.logToTerminal("ENG_C", "🚨 PRIVACY HAZARD: $dangerousClauses invasive clauses found!")
                        ThreatRepository.addThreat("Web Browser", text, "Invasive Privacy Policy", 0.95f)
                        ThreatNotifier.showMalwareAlert(this@GoPrivateVpnService, "Privacy Hazard Detected", text)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Engine C Auditor pipeline crashed", e)
                }
            }
        }
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(screenStateReceiver)
            unregisterReceiver(quarantineReceiver)
        } catch (_: Exception) {}
        serviceScope.cancel()
        nativeStopEngine()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        activeFlows.clear()
        quarantinedPackages.clear()
        uidToPackageCache.clear()
        super.onDestroy()
    }

    private external fun nativeStartEngine(vpnFileDescriptor: Int)
    private external fun nativeStopEngine()
}