@file:Suppress("unused")

package com.goprivate.app.ui.viewmodels

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.data.model.ThreatLog
import com.goprivate.app.data.repository.ThreatRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

class ThreatLogViewModel(
    application: Application,
    private val threatRepository: ThreatRepository
) : AndroidViewModel(application) {

    // 🚨 RISK-BASED FILTERS: Upgraded to match the new UI Chips
    enum class RiskFilter {
        ALL, MALICIOUS, SUSPICIOUS, SAFE
    }

    private val _filter = MutableStateFlow(RiskFilter.ALL)

    // 🚨 THE MASTER DATABASE STREAM
    val allThreatsFlow: StateFlow<List<ThreatLog>> = threatRepository.threatsFlow

    // 🚨 THE MASTER FILTER PIPELINE
    private val filteredMasterFlow = combine(
        threatRepository.threatsFlow,
        _filter
    ) { threats, activeFilter ->
        when (activeFilter) {
            RiskFilter.ALL -> threats
            RiskFilter.MALICIOUS -> threats.filter { it.riskScore >= 0.75f }
            RiskFilter.SUSPICIOUS -> threats.filter { it.riskScore in 0.4f..0.74f }
            RiskFilter.SAFE -> threats.filter { it.riskScore < 0.4f }
        }
    }

    // =========================================================================
    // 🚨 TRI-CORE SPLITTERS: Routes the filtered data to the 3 separate UI Cards
    // =========================================================================

    // ENGINE A: Network Traffic (IDS)
    val engineAThreats: StateFlow<List<ThreatLog>> = filteredMasterFlow.map { list ->
        list.filter {
            it.threatType.contains("Network", ignoreCase = true) ||
                    it.threatType.contains("C2", ignoreCase = true) ||
                    it.threatType.contains("Packet", ignoreCase = true)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // ENGINE B: Static XAI (Sideloads / App Scans)
    val engineBThreats: StateFlow<List<ThreatLog>> = filteredMasterFlow.map { list ->
        list.filter {
            it.threatType.contains("Signature", ignoreCase = true) ||
                    it.threatType.contains("Sideload", ignoreCase = true) ||
                    it.threatType.contains("API", ignoreCase = true) ||
                    it.threatType.contains("Permissions", ignoreCase = true)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // ENGINE C: NLP Privacy Auditor (Policy Scans)
    val engineCThreats: StateFlow<List<ThreatLog>> = filteredMasterFlow.map { list ->
        list.filter {
            it.threatType.contains("Privacy", ignoreCase = true) ||
                    it.threatType.contains("Sharing", ignoreCase = true) ||
                    it.threatType.contains("Data", ignoreCase = true) ||
                    it.threatType.contains("Analyzer", ignoreCase = true)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())


    // =========================================================================

    fun setFilter(filter: RiskFilter) {
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

class ThreatLogViewModelFactory(
    private val application: Application
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(ThreatLogViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return ThreatLogViewModel(
                application = application,
                threatRepository = ThreatRepository
            ) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
    }
}