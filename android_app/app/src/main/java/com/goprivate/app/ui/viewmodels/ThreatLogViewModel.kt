@file:Suppress("unused")

package com.goprivate.app.ui.viewmodels

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.model.ThreatLog
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

class ThreatLogViewModel(
    application: Application,
    private val threatRepository: ThreatRepository
) : AndroidViewModel(application) {

    // 🚨 TRINITY UPGRADE: Added ENGINE_C to complete the Matrix
    enum class ThreatFilter {
        ALL, CRITICAL, WARNING, ENGINE_A, ENGINE_B, ENGINE_C
    }

    private val _filter = MutableStateFlow(ThreatFilter.ALL)

    /**
     * 🚨 THE GLOBAL STATS FIX
     * Exposes the raw, unfiltered database directly to the Fragment.
     * This keeps the top 3 HUD numbers (Engine A, B, C counts) perfectly
     * accurate even when the user filters the list below.
     */
    val allThreatsFlow: StateFlow<List<ThreatLog>> = threatRepository.threatsFlow

    /**
     * 🚨 THE PIPELINE OPTIMIZATION
     * Automatically combines the raw database and the selected Chip Filter.
     * The string-matching perfectly mirrors the strings injected by our 3 Sentinels.
     */
    val threatsFlow: StateFlow<List<ThreatLog>> = combine(
        threatRepository.threatsFlow,
        _filter
    ) { threats, activeFilter ->
        when (activeFilter) {
            ThreatFilter.ALL -> threats

            ThreatFilter.CRITICAL -> threats.filter { it.riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD }
            ThreatFilter.WARNING -> threats.filter { it.riskScore in 0.4f..0.74f }

            // ENGINE A: VPN Network Shield (Catches "Malicious C2 Network Traffic", "Network Anomaly")
            ThreatFilter.ENGINE_A -> threats.filter {
                it.threatType.contains("Network", ignoreCase = true) ||
                        it.threatType.contains("C2", ignoreCase = true)
            }

            // ENGINE B: Static XAI (Catches "Malicious API/Permissions", "Malicious Sideload Signature")
            ThreatFilter.ENGINE_B -> threats.filter {
                it.threatType.contains("Signature", ignoreCase = true) ||
                        it.threatType.contains("Sideload", ignoreCase = true) ||
                        it.threatType.contains("API", ignoreCase = true) ||
                        it.threatType.contains("Permissions", ignoreCase = true)
            }

            // ENGINE C: NLP Privacy Auditor (Catches "Invasive Privacy Policy", "Invasive Data Sharing")
            ThreatFilter.ENGINE_C -> threats.filter {
                it.threatType.contains("Privacy", ignoreCase = true) ||
                        it.threatType.contains("Sharing", ignoreCase = true) ||
                        it.threatType.contains("Data", ignoreCase = true)
            }
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun setFilter(filter: ThreatFilter) {
        _filter.value = filter
    }

    fun clearHistory() {
        threatRepository.clearHistory()
        TelemetryManager.logToTerminal("SYS", "Quarantine logs purged by User Override.")
    }

    fun getTotalThreatsBlocked(): Int {
        return threatRepository.getTotalThreatsBlocked()
    }
}

/**
 * 🚨 FACTORY FIX: Standardized Factory Pattern
 * Note: If you have this Factory duplicated at the bottom of your ThreatLogFragment.kt file,
 * delete the one in the Fragment file and exclusively use this one to prevent compiler confusion!
 */
class ThreatLogViewModelFactory(
    private val application: Application
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(ThreatLogViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return ThreatLogViewModel(
                application = application,
                threatRepository = ThreatRepository // Injects the Singleton directly
            ) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
    }
}