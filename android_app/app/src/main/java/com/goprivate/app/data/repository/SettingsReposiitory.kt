@file:Suppress("unused")

package com.goprivate.app.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.goprivate.app.data.model.DetectionThreshold
import com.goprivate.app.data.model.ThemeMode
import com.goprivate.app.data.model.VpnMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Repository for App Settings.
 * Optimized for strict memory reallocation and thread-safety.
 */
class SettingsRepository(context: Context) {

    // Always use applicationContext to prevent severe memory leaks
    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
        "goprivate_settings", Context.MODE_PRIVATE
    )

    private val _themeMode = MutableStateFlow(loadThemeMode())
    val themeModeFlow: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _detectionThreshold = MutableStateFlow(loadDetectionThreshold())
    val detectionThresholdFlow: StateFlow<DetectionThreshold> = _detectionThreshold.asStateFlow()

    private val _whitelist = MutableStateFlow(loadWhitelist())
    val whitelistFlow: StateFlow<Set<String>> = _whitelist.asStateFlow()

    private val _telemetryEnabled = MutableStateFlow(loadTelemetryEnabled())
    val telemetryEnabledFlow: StateFlow<Boolean> = _telemetryEnabled.asStateFlow()

    private val _vpnMode = MutableStateFlow(loadVpnMode())
    val vpnModeFlow: StateFlow<VpnMode> = _vpnMode.asStateFlow()

    fun setThemeMode(mode: ThemeMode) {
        _themeMode.value = mode
        prefs.edit { putString("theme_mode", mode.name) }
    }

    fun setDetectionThreshold(threshold: DetectionThreshold) {
        _detectionThreshold.value = threshold
        prefs.edit { putFloat("detection_threshold", threshold.value) }
    }

    /**
     * 🚨 SET REALLOCATION FIX
     * Android SharedPreferences requires a completely new Set object in memory to trigger a save.
     */
    fun addToWhitelist(packageName: String) {
        val current = _whitelist.value.toMutableSet()
        if (current.add(packageName)) {
            val newSet = current.toSet() // Force new memory address
            _whitelist.value = newSet
            saveWhitelist(newSet)
        }
    }

    fun removeFromWhitelist(packageName: String) {
        val current = _whitelist.value.toMutableSet()
        if (current.remove(packageName)) {
            val newSet = current.toSet() // Force new memory address
            _whitelist.value = newSet
            saveWhitelist(newSet)
        }
    }

    fun setTelemetryEnabled(enabled: Boolean) {
        _telemetryEnabled.value = enabled
        prefs.edit { putBoolean("telemetry_enabled", enabled) }
    }

    fun setVpnMode(mode: VpnMode) {
        _vpnMode.value = mode
        prefs.edit { putString("vpn_mode", mode.name) }
    }

    // --- DISK LOADERS ---

    private fun loadThemeMode(): ThemeMode {
        val name = prefs.getString("theme_mode", ThemeMode.DARK.name) ?: ThemeMode.DARK.name
        return try { ThemeMode.valueOf(name) } catch (e: IllegalArgumentException) { ThemeMode.DARK }
    }

    private fun loadDetectionThreshold(): DetectionThreshold {
        val value = prefs.getFloat("detection_threshold", 0.50f)
        return DetectionThreshold.entries.find { it.value == value } ?: DetectionThreshold.BALANCED
    }

    private fun loadWhitelist(): Set<String> {
        // Return a strict copy to prevent external mutation errors
        return prefs.getStringSet("whitelist", emptySet())?.toSet() ?: emptySet()
    }

    private fun saveWhitelist(whitelist: Set<String>) {
        prefs.edit { putStringSet("whitelist", whitelist) }
    }

    private fun loadTelemetryEnabled(): Boolean {
        return prefs.getBoolean("telemetry_enabled", true)
    }

    private fun loadVpnMode(): VpnMode {
        val name = prefs.getString("vpn_mode", VpnMode.AUTO.name) ?: VpnMode.AUTO.name
        return try { VpnMode.valueOf(name) } catch (e: IllegalArgumentException) { VpnMode.AUTO }
    }
}