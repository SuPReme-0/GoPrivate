@file:Suppress("unused")

package com.goprivate.app.data.model

/**
 * App scan result for Scanner UI
 * Contains app metadata, risk assessment, scan metadata, and Trinity Network State.
 */
data class AppScanResult(
    val packageName: String,
    val appName: String,
    val riskScore: Float,
    val permissions: List<String> = emptyList(),
    val activeThreatFeatures: List<String> = emptyList(),
    val scanTimestamp: Long = System.currentTimeMillis(),
    val isIsolated: Boolean = false // 🚨 TRINITY UPGRADE: Tracks Active Network Quarantine
) {
    val riskLevel: RiskLevel get() = when {
        riskScore < 0.4f -> RiskLevel.SAFE
        riskScore < 0.7f -> RiskLevel.SUSPICIOUS
        else -> RiskLevel.MALICIOUS
    }

    val formattedTimestamp: String get() {
        val diff = System.currentTimeMillis() - scanTimestamp
        return when {
            diff < 60_000 -> "Just now"
            diff < 3_600_000 -> "${diff / 60_000}m ago"
            diff < 86_400_000 -> "${diff / 3_600_000}h ago"
            else -> "${diff / 86_400_000}d ago"
        }
    }
}