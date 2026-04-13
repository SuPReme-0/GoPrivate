@file:Suppress("unused")

package com.goprivate.app.ui.viewmodels

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.goprivate.app.data.model.DetectionThreshold
import com.goprivate.app.data.model.SettingsState
import com.goprivate.app.data.model.VpnMode
import com.goprivate.app.data.repository.SettingsRepository
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

class SettingsViewModel(
    application: Application,
    private val settingsRepository: SettingsRepository
) : AndroidViewModel(application) {

    // 🚨 OS Permission States (These live in the ViewModel because they aren't saved to disk)
    private val _notificationsEnabled = MutableStateFlow(true)
    private val _fileAccessEnabled = MutableStateFlow(true)

    /**
     * 🚨 THE PIPELINE FIX: Zero-Duplication State Management.
     * We combine the Repository's permanent disk flows with the OS permission memory flows.
     * If ANY of these 5 flows change, the UI instantly updates. No race conditions.
     */
    val settingsState: StateFlow<SettingsState> = combine(
        settingsRepository.detectionThresholdFlow,
        settingsRepository.telemetryEnabledFlow,
        settingsRepository.vpnModeFlow,
        _notificationsEnabled,
        _fileAccessEnabled
    ) { threshold, telemetry, vpnMode, notifs, fileAccess ->
        SettingsState(
            detectionThreshold = threshold,
            telemetryEnabled = telemetry,
            vpnMode = vpnMode,
            notificationsEnabled = notifs,
            fileAccessEnabled = fileAccess
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000), // Efficient: Stops collecting when UI is hidden
        initialValue = SettingsState()
    )

    fun setDetectionThreshold(threshold: DetectionThreshold) {
        settingsRepository.setDetectionThreshold(threshold)
    }

    fun toggleTelemetry(enabled: Boolean) {
        settingsRepository.setTelemetryEnabled(enabled)
    }

    fun setVpnMode(mode: VpnMode) {
        settingsRepository.setVpnMode(mode)
    }

    fun updateOsPermissionState(notifications: Boolean, fileAccess: Boolean) {
        _notificationsEnabled.value = notifications
        _fileAccessEnabled.value = fileAccess
    }

    fun clearThreatHistory() {
        ThreatRepository.clearHistory()
    }
}

/**
 * Enterprise Factory Pattern for Dependency Injection
 */
class SettingsViewModelFactory(
    private val application: Application
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(SettingsViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return SettingsViewModel(
                application,
                SettingsRepository(application) // Provide the concrete repo here
            ) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
    }
}