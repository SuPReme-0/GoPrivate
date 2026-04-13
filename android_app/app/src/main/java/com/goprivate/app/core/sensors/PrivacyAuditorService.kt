@file:Suppress("SpellCheckingInspection")

package com.goprivate.app.core.sensors

import android.accessibilityservice.AccessibilityService
import android.annotation.SuppressLint
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.core.notifications.ThreatNotifier
import com.goprivate.app.data.ml.EngineCNLPManager
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.text.BreakIterator

@SuppressLint("AccessibilityPolicy")
class PrivacyAuditorService : AccessibilityService() {

    companion object {
        private const val TAG = "PrivacyAuditor"

        // 🚨 NATIVE APP REGEX UPGRADE: Added "information we collect", "data policy", "data we share" to catch Instagram/Meta native screens.
        private val LEGAL_PAGE_REGEX = Regex(
            "\\b(privacy policy|terms of service|end user license|data policy|terms and conditions|cookie policy|privacy notice|terms of use|privacy center|how we use your data|information we collect|data we share|privacy guidelines)\\b",
            RegexOption.IGNORE_CASE
        )

        private val CONSENT_KEYWORDS = listOf(
            "agree", "accept", "allow", "consent", "i understand", "got it", "continue", "proceed", "ok"
        )

        private val SAFE_DOMAINS = listOf(
            "google.com", "duckduckgo.com", "bing.com", "yahoo.com", "wikipedia.org"
        )

        private val HIGH_RISK_MATRIX = Regex(
            "\\b(sell|share|third-party|track|advertising|partners|affiliates|biometric|location|device info|browsing history|cross-device|profiling|keystroke|recording|voice|retention|collect|gather|usage data)\\b",
            RegexOption.IGNORE_CASE
        )

        private val IGNORED_PACKAGES = listOf("com.google.android.inputmethod.latin", "com.android.systemui","com.goprivate.app")
    }

    private val scannedSentenceHashes = mutableSetOf<Int>()
    private var activeTargetPackage = ""
    private var isTargetLocked = false
    private var lastThrottleTime = 0L

    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.d(TAG, "🔌 Continuous Sweep Auditor Connected & Initialized.")
    }

    data class ScreenContext(
        val rawText: String,
        val hasConsentAction: Boolean,
        val isSafeDomain: Boolean
    )

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val packageName = event.packageName?.toString() ?: return

        if (IGNORED_PACKAGES.contains(packageName)) return

        // 🚨 OS-LEVEL WIPE: If the user changes screens internally or clicks a link, the OS fires this.
        // We drop the lock and wipe memory so we don't accidentally scan their DMs thinking it's still a privacy policy!
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            if (isTargetLocked) {
                Log.d(TAG, "🔄 OS Window State Changed. Dropping target lock and wiping memory.")
                isTargetLocked = false
                scannedSentenceHashes.clear()
            }
        }

        if (packageName != activeTargetPackage) {
            activeTargetPackage = packageName
            isTargetLocked = false
            scannedSentenceHashes.clear()
        }

        val now = System.currentTimeMillis()
        if (now - lastThrottleTime < 400) return
        lastThrottleTime = now

        serviceScope.launch {
            val rootNode = rootInActiveWindow ?: return@launch
            val screenContext = extractScreenContext(rootNode)

            if (screenContext.isSafeDomain) {
                isTargetLocked = false
                return@launch
            }
            if (screenContext.rawText.length < 50) return@launch

            val hasLegalText = LEGAL_PAGE_REGEX.containsMatchIn(screenContext.rawText)
            if (hasLegalText) {
                if (!isTargetLocked) {
                    Log.d(TAG, "🎯 TARGET LOCKED: Privacy policy detected. Continuous scanning engaged.")
                    TelemetryManager.logToTerminal("SYS", "Target Lock Acquired: Continuous XAI auditing engaged on [$packageName].")
                }
                isTargetLocked = true
            }

            if (isTargetLocked || screenContext.hasConsentAction) {
                runLiveScreenAudit(screenContext.rawText, packageName)
            }
        }
    }

    private fun extractScreenContext(root: AccessibilityNodeInfo): ScreenContext {
        val textBuilder = java.lang.StringBuilder(8192)
        var foundConsentAction = false
        var isUrlSafe = false

        val stack = ArrayDeque<AccessibilityNodeInfo>()
        stack.addLast(root)

        val maxExecutionTimeMs = 80L
        val startTime = System.currentTimeMillis()

        while (stack.isNotEmpty() && (System.currentTimeMillis() - startTime) < maxExecutionTimeMs) {
            val node = stack.removeLast()

            val nodeText = node.text?.toString()?.trim() ?: node.contentDescription?.toString()?.trim() ?: ""

            // URL Safe check decoupled from memory wiping
            val viewId = node.viewIdResourceName ?: ""
            if (viewId.contains("url_bar", ignoreCase = true) || nodeText.startsWith("http", ignoreCase = true) || nodeText.startsWith("www.", ignoreCase = true)) {
                val extractedUrl = nodeText.lowercase()
                isUrlSafe = SAFE_DOMAINS.any { extractedUrl.contains(it) } && !extractedUrl.contains("policy")

                if (isUrlSafe) {
                    return ScreenContext(
                        rawText = "",
                        hasConsentAction = false,
                        isSafeDomain = true
                    )
                }
            }

            if (nodeText.length > 3) {
                textBuilder.append(nodeText)

                val lastChar = nodeText.last()
                if (lastChar != '.' && lastChar != '!' && lastChar != '?') {
                    textBuilder.append(". ")
                } else {
                    textBuilder.append(" ")
                }

                if (!foundConsentAction) {
                    if (CONSENT_KEYWORDS.any { nodeText.contains(it, ignoreCase = true) }) {
                        foundConsentAction = true
                    }
                }
            }

            for (i in node.childCount - 1 downTo 0) {
                node.getChild(i)?.let { childNode -> stack.addLast(childNode) }
            }
        }

        return ScreenContext(
            rawText = textBuilder.toString(),
            hasConsentAction = foundConsentAction,
            isSafeDomain = false
        )
    }

    private fun runLiveScreenAudit(screenText: String, browserPackage: String) {
        serviceScope.launch {
            try {
                if (!EngineCNLPManager.isReady()) {
                    EngineCNLPManager.initialize(applicationContext)
                }

                val iterator = BreakIterator.getSentenceInstance()
                iterator.setText(screenText)

                val freshRadioactiveChunks = mutableListOf<Pair<String, Int>>()
                var start = iterator.first()
                var end = iterator.next()

                while (end != BreakIterator.DONE) {
                    val sentence = screenText.substring(start, end).trim()

                    if (sentence.length > 15) {
                        val sentenceHash = sentence.hashCode()

                        if (!scannedSentenceHashes.contains(sentenceHash)) {

                            val gravityScore = HIGH_RISK_MATRIX.findAll(sentence).count()

                            if (gravityScore > 0) {
                                freshRadioactiveChunks.add(Pair(sentence, gravityScore))
                            }

                            scannedSentenceHashes.add(sentenceHash)
                        }
                    }

                    start = end
                    end = iterator.next()
                }

                if (freshRadioactiveChunks.isEmpty()) {
                    return@launch
                }

                val topRadioactiveChunks = freshRadioactiveChunks
                    .sortedByDescending { it.second }
                    .take(3)
                    .map { it.first }

                TelemetryManager.logToTerminal("NLP", "Scroll Sync: Isolated ${topRadioactiveChunks.size} fresh payloads. Executing AI...")

                val results = EngineCNLPManager.analyzePolicyClauses(topRadioactiveChunks)

                var dangerousClauses = 0
                var maxConfidence = 0f
                val xaiReport = java.lang.StringBuilder("🚨 XAI FORENSIC REPORT:")

                results.forEachIndexed { index, (label, confidence) ->
                    if (confidence > 65f && (label.contains("data") || label.contains("share") || label.contains("track") || label.contains("ad") || label.contains("collect"))) {
                        dangerousClauses++
                        if (confidence > maxConfidence) maxConfidence = confidence

                        val rawSnippet = topRadioactiveChunks.getOrNull(index) ?: "Data clause hidden"
                        val safeSnippet = if (rawSnippet.length > 65) {
                            rawSnippet.substring(0, 65).replace("\n", " ") + "..."
                        } else {
                            rawSnippet.replace("\n", " ")
                        }

                        xaiReport.append("\n      └─ [$label] \"$safeSnippet\"")
                    }
                }

                if (dangerousClauses >= 1) {
                    val riskScore = maxConfidence / 100f

                    TelemetryManager.logToTerminal("WRN", "HAZARD DETECTED: $dangerousClauses invasive clauses confirmed by AI!")
                    TelemetryManager.logToTerminal("XAI", xaiReport.toString())

                    TelemetryManager.logThreatBlocked("Live Screen Audit", "NLP Privacy Auditor", riskScore)
                    ThreatRepository.addThreat("App ($browserPackage)", "Privacy Policy Analyzer", "Invasive Data Collection", riskScore)
                    ThreatNotifier.showMalwareAlert(this@PrivacyAuditorService, "Privacy Hazard Detected", "AI verified invasive data collection terms on this page.")
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Live Auditor crashed", e)
            }
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "🛑 Accessibility Toggled OFF. Executing OS-Level Kill Switch...")
        serviceScope.cancel()
        EngineCNLPManager.shutdown()
        super.onDestroy()
    }

    override fun onInterrupt() {}
}