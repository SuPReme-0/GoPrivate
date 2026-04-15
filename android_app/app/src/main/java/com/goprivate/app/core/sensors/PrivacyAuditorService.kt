@file:Suppress("SpellCheckingInspection", "DEPRECATION")

package com.goprivate.app.core.sensors

import android.accessibilityservice.AccessibilityService
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.content.edit
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.core.notifications.ThreatNotifier
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.ml.EngineCNLPManager
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.net.HttpURLConnection
import java.net.URL
import java.text.BreakIterator
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.collections.ArrayDeque

@SuppressLint("AccessibilityPolicy")
class PrivacyAuditorService : AccessibilityService() {

    companion object {
        private const val TAG = "PrivacyAuditor"

        private val LEGAL_PAGE_REGEX = Regex(
            "(privacy policy|terms of service|end user license|data policy|terms and conditions|cookie policy|privacy notice|terms of use|privacy center|how we use your data|information we collect|data we share|privacy guidelines|help center|meta privacy|legal & policies)",
            RegexOption.IGNORE_CASE
        )

        private val CONSENT_KEYWORDS = listOf(
            "agree", "accept", "allow", "consent", "i understand", "got it", "continue", "proceed", "ok"
        )

        private val HIGH_RISK_MATRIX = Regex(
            "\\b(sell|share|third-party|track|advertising|partners|affiliates|biometric|location|device info|browsing history|cross-device|profiling|keystroke|recording|voice|retention|collect|gather|usage data|cookie|personal data|personal information|identifier|ip address|health|financial|analytics|pixel|demographic)\\b",
            RegexOption.IGNORE_CASE
        )

        private val IGNORED_PACKAGES = listOf("com.google.android.inputmethod.latin", "com.android.systemui", "com.goprivate.app")

        // 🚨 EXPANDED LAUNCHER LIST: Added robust OEM support to instantly kill ghost scans
        private val LAUNCHERS = listOf(
            "com.sec.android.app.launcher", "com.google.android.apps.nexuslauncher",
            "com.miui.home", "com.teslacoilsw.launcher", "com.oneplus.margin",
            "com.android.launcher", "com.android.launcher3", "com.coloros.launcher",
            "com.bbk.launcher2", "com.huawei.android.launcher", "com.oppo.launcher",
            "com.vivo.launcher", "com.sec.android.app.easylauncher"
        )
    }

    private val scannedSentenceHashes = Collections.newSetFromMap(ConcurrentHashMap<Int, Boolean>())
    @Volatile private var activeTargetPackage = ""
    @Volatile private var isTargetLocked = false
    @Volatile private var lastLegalContextTime = 0L
    @Volatile private var lastThrottleTime = 0L
    @Volatile private var lastFetchedUrl = ""

    private val isNlpBusy = AtomicBoolean(false)
    private val domDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private val serviceScope = CoroutineScope(domDispatcher + SupervisorJob())

    private var dynamicInstallReceiver: BroadcastReceiver? = null
    private var trailingEdgeJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.d(TAG, "🔌 Continuous Sweep Auditor Connected & Initialized.")

        try {
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }

            dynamicInstallReceiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    val action = intent.action
                    val packageName = intent.data?.schemeSpecificPart ?: return
                    val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                    if (action == Intent.ACTION_PACKAGE_ADDED && isReplacing) return

                    Log.d(TAG, "📦 Sideload detected: $packageName. Executing Vanguard Scan...")
                    serviceScope.launch { executeVanguardScan(packageName) }
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(dynamicInstallReceiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                registerReceiver(dynamicInstallReceiver, filter)
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to dynamically bind AppInstallReceiver", e)
        }
    }

    private suspend fun executeVanguardScan(targetPackage: String) {
        try {
            val appName = try { packageManager.getApplicationInfo(targetPackage, 0).loadLabel(packageManager).toString() } catch (_: Exception) { targetPackage }

            sendBroadcast(Intent("com.goprivate.app.SCAN_PROGRESS").apply {
                putExtra("isScanning", true); putExtra("progress", 50); putExtra("totalApps", 1); putExtra("scannedApps", 0)
            })

            if (!EngineBStaticManager.isReady()) EngineBStaticManager.initialize(applicationContext)
            var (riskScore, forensicReport) = EngineBStaticManager.analyzeApp(targetPackage, applicationContext)

            if (targetPackage == packageName) riskScore = 0.0f

            val featureString = forensicReport.joinToString(";;;")
            val serializedData = "$riskScore|${System.currentTimeMillis()}|false|$featureString"

            getSharedPreferences("goprivate_forensic_cache", Context.MODE_PRIVATE).edit {
                putString(targetPackage, serializedData)
            }

            if (riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD) {
                TelemetryManager.logThreatBlocked(appName, "Sideload Interceptor", riskScore)
                ThreatRepository.addThreat(appName, targetPackage, "Malicious Sideload", riskScore)
                ThreatNotifier.showMalwareAlert(applicationContext, "🚨 Sideload Threat", "$appName is malicious. Tap to purge.")
            } else {
                TelemetryManager.logToTerminal("ENG_B", "✅ $appName verified clean. Score: $riskScore")
            }

            sendBroadcast(Intent("com.goprivate.app.APP_SCANNED_RESULT").apply {
                putExtra("packageName", targetPackage); putExtra("riskScore", riskScore)
            })
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to process sideload", e)
        } finally {
            sendBroadcast(Intent("com.goprivate.app.SCAN_PROGRESS").apply {
                putExtra("isScanning", false); putExtra("progress", 100); putExtra("totalApps", 1); putExtra("scannedApps", 1)
            })
        }
    }

    data class ScreenContext(val rawText: String, val hasConsentAction: Boolean, val extractedUrl: String?)

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val currentPackage = event.packageName?.toString() ?: return
        if (IGNORED_PACKAGES.contains(currentPackage)) return

        // 🚨 GHOST SCANNING FIX: Dynamic wildcard match for ANY home screen launcher
        if (LAUNCHERS.any { currentPackage.contains(it, true) } || currentPackage.contains("launcher", true) || currentPackage.contains("home", true)) {
            if (isTargetLocked) {
                Log.d(TAG, "🏠 Home Screen detected. Violently dropping lock.")
                isTargetLocked = false
                activeTargetPackage = ""
                scannedSentenceHashes.clear()
            }
            return
        }

        activeTargetPackage = currentPackage

        val now = System.currentTimeMillis()
        if (now - lastThrottleTime >= 800) {
            lastThrottleTime = now
            triggerDomScan(currentPackage)
        } else {
            trailingEdgeJob?.cancel()
            trailingEdgeJob = serviceScope.launch {
                delay(1200)
                lastThrottleTime = System.currentTimeMillis()
                triggerDomScan(currentPackage)
            }
        }
    }

    private fun triggerDomScan(currentPackage: String) {
        serviceScope.launch {
            val roots = mutableListOf<AccessibilityNodeInfo>()

            try {
                val screenWindows = windows
                if (screenWindows.isNullOrEmpty()) {
                    rootInActiveWindow?.let { roots.add(it) }
                } else {
                    for (window in screenWindows) {
                        window.root?.let { roots.add(it) }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ Window IPC Cache fault, falling back to active root.", e)
                rootInActiveWindow?.let { roots.add(it) }
            }

            if (roots.isEmpty()) return@launch

            val screenContext = extractScreenContext(roots)
            roots.forEach { it.recycle() }

            var validUrl: String? = null
            val rawExtracted = screenContext.extractedUrl
            if (rawExtracted != null && rawExtracted.contains(".") && !rawExtracted.contains(" ")) {
                val lowerUrl = rawExtracted.lowercase()
                if (!lowerUrl.contains("google.com/search") && !lowerUrl.contains("bing.com/search") && !lowerUrl.contains("duckduckgo.com")) {
                    validUrl = rawExtracted
                }
            }

            if (validUrl != null && validUrl != lastFetchedUrl) {
                lastFetchedUrl = validUrl
                Log.d(TAG, "🌐 Meta Accessibility Bypass Triggered! Fetching: $validUrl")
                TelemetryManager.logToTerminal("SYS", "DOM Obfuscation Detected. Launching Parallel URL Fetch...")

                executeBackgroundUrlFetch(validUrl, currentPackage, screenContext.rawText, screenContext.hasConsentAction)
                return@launch
            }

            processExtractedText(screenContext.rawText, currentPackage, screenContext.hasConsentAction, isFromUrlFetch = false, hasValidUrl = (validUrl != null))
        }
    }

    private fun extractScreenContext(roots: List<AccessibilityNodeInfo>): ScreenContext {
        val textBuilder = StringBuilder(8192)
        var foundConsentAction = false
        var capturedUrl: String? = null

        val queue = ArrayDeque<AccessibilityNodeInfo>()
        roots.forEach { queue.addLast(it) }

        val maxExecutionTimeMs = 400L
        val startTime = System.currentTimeMillis()
        var nodeCount = 0

        while (queue.isNotEmpty() && (System.currentTimeMillis() - startTime) < maxExecutionTimeMs && nodeCount < 10000) {
            val node = queue.removeFirst()
            nodeCount++

            val nodeText = node.text?.toString()?.trim() ?: node.contentDescription?.toString()?.trim() ?: ""
            val nodeTextLower = nodeText.lowercase()

            val viewId = node.viewIdResourceName?.lowercase() ?: ""
            val className = node.className?.toString()?.lowercase() ?: ""

            if (viewId.contains("url") || className.contains("edittext") || nodeTextLower.startsWith("http") || nodeTextLower.startsWith("www.")) {
                if (nodeTextLower.contains("policy") || nodeTextLower.contains("privacy") || nodeTextLower.contains("terms") || nodeTextLower.contains("data") || nodeTextLower.contains("help")) {
                    capturedUrl = nodeText
                }
            }

            if (nodeText.isNotEmpty()) {
                textBuilder.append(nodeText).append(" ")

                if (!foundConsentAction && CONSENT_KEYWORDS.any { nodeTextLower.contains(it) }) {
                    foundConsentAction = true
                }
            }

            for (i in 0 until node.childCount) {
                node.getChild(i)?.let { queue.addLast(it) }
            }

            if (!roots.contains(node)) {
                node.recycle()
            }
        }

        while (queue.isNotEmpty()) {
            val leftover = queue.removeFirst()
            if (!roots.contains(leftover)) leftover.recycle()
        }

        return ScreenContext(
            rawText = textBuilder.toString(),
            hasConsentAction = foundConsentAction,
            extractedUrl = capturedUrl
        )
    }

    private fun executeBackgroundUrlFetch(urlString: String, browserPackage: String, fallbackText: String, hasConsent: Boolean) {
        serviceScope.launch(Dispatchers.IO) {
            try {
                var targetUrl = urlString
                if (!targetUrl.startsWith("http")) {
                    targetUrl = "https://$targetUrl"
                }

                val url = URL(targetUrl)
                val connection = url.openConnection() as HttpURLConnection

                connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")
                connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                connection.connectTimeout = 5000
                connection.readTimeout = 8000

                val responseCode = connection.responseCode
                if (responseCode in 200..299) {
                    val inputStream = connection.inputStream
                    val htmlText = inputStream.bufferedReader().use { it.readText().take(150000) }

                    val bodyRegex = Regex("<body[^>]*>(.*?)</body>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                    val bodyMatch = bodyRegex.find(htmlText)?.groupValues?.get(1) ?: htmlText

                    val cleanText = bodyMatch
                        .replace(Regex("<(p|div|br|li|h[1-6])[^>]*>", setOf(RegexOption.IGNORE_CASE)), ". ")
                        .replace(Regex("<script[^>]*>.*?</script>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)), " ")
                        .replace(Regex("<style[^>]*>.*?</style>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)), " ")
                        .replace(Regex("<[^>]*>"), " ")
                        .replace(Regex("\\s+"), " ")
                        .replace(Regex("\\.\\s*\\."), ".")
                        .trim()

                    val riskCount = HIGH_RISK_MATRIX.findAll(cleanText).count()
                    if (cleanText.length < 500 || riskCount == 0) {
                        Log.w(TAG, "⚠️ Phantom Fetch returned an empty React Shell. Falling back to Native DOM.")
                        processExtractedText(fallbackText, browserPackage, hasConsent, isFromUrlFetch = false, hasValidUrl = true)
                        return@launch
                    }

                    Log.d(TAG, "✅ Phantom Fetch Success. Extracted ${cleanText.length} characters. Pushing to NLP Pipeline...")
                    processExtractedText(cleanText, browserPackage, hasConsent, isFromUrlFetch = true, hasValidUrl = true)
                    return@launch
                } else {
                    Log.e(TAG, "❌ HTTP $responseCode received for $urlString")
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Phantom Fetch Exception for $urlString", e)
            }

            Log.d(TAG, "🛡️ Fallback Activated: Bypassing HTTP failure and utilizing Native BFS Screen Data.")
            processExtractedText(fallbackText, browserPackage, hasConsent, isFromUrlFetch = false, hasValidUrl = true)
        }
    }

    private fun processExtractedText(text: String, currentPackage: String, hasConsent: Boolean, isFromUrlFetch: Boolean, hasValidUrl: Boolean) {
        if (text.length < 30) return

        val hasLegalHeader = LEGAL_PAGE_REGEX.containsMatchIn(text)
        val riskWordCount = HIGH_RISK_MATRIX.findAll(text).count()

        if (hasLegalHeader || riskWordCount >= 3 || isFromUrlFetch || hasValidUrl) {
            if (!isTargetLocked) {
                Log.d(TAG, "🎯 TARGET LOCKED: Context Verified natively in [$currentPackage].")
                TelemetryManager.logToTerminal("SYS", "Target Lock Acquired: Auditing Interface in [$currentPackage].")
            }
            isTargetLocked = true
            lastLegalContextTime = System.currentTimeMillis()
        } else if (isTargetLocked && (System.currentTimeMillis() - lastLegalContextTime > 15000)) {
            Log.d(TAG, "🔄 Target Lock Decayed. Dropping lock.")
            isTargetLocked = false
            scannedSentenceHashes.clear()
        }

        if (isTargetLocked || hasConsent) {
            runLiveScreenAudit(text, browserPackage = currentPackage, isFullDocument = isFromUrlFetch)
        }
    }

    // 🚨 PIPELINE UPGRADE: Differentiates between Full Background Documents and Native Scroll chunks.
    private fun runLiveScreenAudit(screenText: String, browserPackage: String, isFullDocument: Boolean) {
        serviceScope.launch {
            try {
                if (!EngineCNLPManager.isReady()) EngineCNLPManager.initialize(applicationContext)

                val iterator = BreakIterator.getSentenceInstance()
                iterator.setText(screenText)

                val freshRadioactiveChunks = mutableListOf<Pair<String, Int>>()
                var start = iterator.first()
                var end = iterator.next()

                while (end != BreakIterator.DONE) {
                    val sentence = screenText.substring(start, end).trim()
                    val safeSentence = if (sentence.length > 2000) sentence.substring(0, 2000) else sentence

                    if (safeSentence.length > 15) {
                        val sentenceHash = safeSentence.hashCode()

                        if (!scannedSentenceHashes.contains(sentenceHash)) {
                            val gravityScore = HIGH_RISK_MATRIX.findAll(safeSentence).count()
                            freshRadioactiveChunks.add(Pair(safeSentence, gravityScore))
                            scannedSentenceHashes.add(sentenceHash)
                        }
                    }
                    start = end
                    end = iterator.next()
                }

                if (freshRadioactiveChunks.isEmpty()) return@launch

                // 🚨 BATCHING OPTIMIZATION:
                // If it's a full 150KB HTML download, we extract the Top 20 most highly-radioactive clauses instantly.
                // If it's a native scroll, we take the top 12 currently visible on the screen.
                val sortedChunks = freshRadioactiveChunks.sortedByDescending { it.second }
                val topRadioactiveChunks = if (isFullDocument) {
                    sortedChunks.filter { it.second > 0 }.take(20).map { it.first }
                } else {
                    sortedChunks.take(12).map { it.first }
                }

                if (topRadioactiveChunks.isEmpty()) return@launch

                TelemetryManager.logToTerminal("NLP", "Pipeline Sync: Isolated ${topRadioactiveChunks.size} fresh payloads. Executing AI...")

                val results = mutableListOf<Pair<String, Float>>()
                for (chunk in topRadioactiveChunks) {
                    val result = EngineCNLPManager.analyzePolicyClause(chunk, isSilent = true)
                    results.add(result)
                }

                var dangerousClauses = 0
                var maxConfidence = 0f
                val xaiReportText = StringBuilder("🚨 XAI FORENSIC REPORT:")
                val xaiClauses = mutableListOf<String>()
                val xaiLabels = mutableListOf<String>()
                val xaiScores = mutableListOf<Float>()

                results.forEachIndexed { index, (label, confidence) ->
                    val normalizedLabel = label.lowercase()
                    val isThreatLabel = normalizedLabel.contains("data") || normalizedLabel.contains("share") ||
                            normalizedLabel.contains("track") || normalizedLabel.contains("ad") ||
                            normalizedLabel.contains("collect") || normalizedLabel.contains("phishing") ||
                            normalizedLabel.contains("malware")

                    // 🚨 SUSPICIOUS THRESHOLD FIX: Lowered gate to 40% (0.40) to match the UI Risk Filters!
                    if (confidence >= 40f && isThreatLabel) {
                        dangerousClauses++
                        if (confidence > maxConfidence) maxConfidence = confidence

                        val rawSnippet = topRadioactiveChunks.getOrNull(index) ?: "Data clause hidden"
                        val safeSnippet = if (rawSnippet.length > 65) rawSnippet.substring(0, 65).replace("\n", " ") + "..." else rawSnippet.replace("\n", " ")

                        xaiReportText.append("\n      └─ [$label] \"$safeSnippet\"")

                        xaiClauses.add(rawSnippet)
                        xaiLabels.add(label)
                        xaiScores.add(confidence)
                    }
                }

                if (dangerousClauses >= 1) {
                    val riskScore = maxConfidence / 100f
                    TelemetryManager.logToTerminal("WRN", "HAZARD DETECTED: $dangerousClauses invasive clauses confirmed by AI!")
                    TelemetryManager.logToTerminal("XAI", xaiReportText.toString())

                    TelemetryManager.logThreatBlocked("Live Screen Audit", "NLP Privacy Auditor", riskScore)
                    ThreatRepository.addThreat("App ($browserPackage)", "Privacy Policy Analyzer", "Invasive Data Collection", riskScore)
                    ThreatNotifier.showMalwareAlert(this@PrivacyAuditorService, "Privacy Hazard Detected", "AI verified invasive data collection terms on this page.")

                    val xaiIntent = Intent("com.goprivate.app.ACTION_NLP_XAI_REPORT").apply {
                        putExtra("packageName", browserPackage)
                        putExtra("riskScore", riskScore)
                        putExtra("dangerousClauseCount", dangerousClauses)
                        putExtra("xaiClauses", xaiClauses.toTypedArray())
                        putExtra("xaiLabels", xaiLabels.toTypedArray())
                        putExtra("xaiScores", xaiScores.toFloatArray())
                    }
                    sendBroadcast(xaiIntent)
                } else {
                    TelemetryManager.logToTerminal("INF", "Scan Complete: Policy verified as SAFE. No broadcast threat detected.")

                    val safeIntent = Intent("com.goprivate.app.ACTION_NLP_XAI_REPORT").apply {
                        putExtra("packageName", browserPackage)
                        putExtra("riskScore", 0.0f)
                        putExtra("dangerousClauseCount", 0)
                        putExtra("xaiClauses", emptyArray<String>())
                        putExtra("xaiLabels", emptyArray<String>())
                        putExtra("xaiScores", FloatArray(0))
                    }
                    sendBroadcast(safeIntent)
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Live Auditor crashed", e)
            }
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "🛑 Accessibility Toggled OFF. Executing OS-Level Kill Switch...")
        try { dynamicInstallReceiver?.let { unregisterReceiver(it) } } catch (e: Exception) { Log.e(TAG, "Error unregistering dynamic receiver", e) }
        serviceScope.cancel()
        EngineCNLPManager.shutdown()
        super.onDestroy()
    }

    override fun onInterrupt() {}
}