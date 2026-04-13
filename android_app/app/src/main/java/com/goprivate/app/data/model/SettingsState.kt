
package com.goprivate.app.data.model

data class SettingsState(
    // Removed ThemeMode entirely
    val detectionThreshold: DetectionThreshold = DetectionThreshold.BALANCED,
    val telemetryEnabled: Boolean = true,
    val vpnMode: VpnMode = VpnMode.AUTO,
    val notificationsEnabled: Boolean = false,
    val fileAccessEnabled: Boolean = false
)


enum class VpnMode { AUTO, MANUAL, ALWAYS_ON }