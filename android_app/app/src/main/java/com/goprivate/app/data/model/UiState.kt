    @file:Suppress("unused")

    package com.goprivate.app.data.model

    /**
     * Single source of truth for the Dashboard UI.
     */
    data class DashboardState(
        val scannedCount: Int = 0,
        val blockedCount: Int = 0,
        val protectedMb: Float = 0f,
        val batterySaved: Float = 0f,
        val networkData: List<NetworkDataPoint> = emptyList(),
        val terminalLog: List<String> = emptyList(), // Linked to Engine C & SharedFlows
        val shieldActive: Boolean = false,
        val isLoading: Boolean = true,
        val packetRate: Float = 0f
    )

    /**
     * Data point for real-time network graph
     */
    data class NetworkDataPoint(
        val timestamp: Long,
        val packetRate: Float
    )

    /**
     * Threat log entry for history display
     */
    data class ThreatLog(
        val id: Long = System.currentTimeMillis(),
        val appName: String,
        val packageName: String,
        val threatType: String,
        val riskScore: Float,
        val timestamp: Long = System.currentTimeMillis()
    ) {
        val isBlocked: Boolean = true

        // 🚨 CRITICAL: Your ThreatTickerAdapter needs this to compile!
        val formattedTimestamp: String get() {
            val diff = System.currentTimeMillis() - timestamp
            return when {
                diff < 60_000 -> "Just now"
                diff < 3_600_000 -> "${diff / 60_000}m ago"
                diff < 86_400_000 -> "${diff / 3_600_000}h ago"
                else -> "${diff / 86_400_000}d ago"
            }
        }

        // 🚨 CRITICAL: Used for color-coding the UI based on risk severity
        val riskLevel: RiskLevel get() = when {
            riskScore < 0.2f -> RiskLevel.SAFE
            riskScore < 0.7f -> RiskLevel.SUSPICIOUS
            else -> RiskLevel.MALICIOUS
        }
    }

    enum class RiskLevel {
        SAFE, SUSPICIOUS, MALICIOUS
    }