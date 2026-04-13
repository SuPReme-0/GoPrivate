@file:Suppress("unused", "MemberVisibilityCanBePrivate")

package com.goprivate.app.data.repository

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.goprivate.app.data.model.ThreatLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * 🛡️ THE THREAT VAULT (SINGLETON)
 * Upgraded with Disk-Backed Persistence. Threats now survive OS kills and reboots.
 */
@SuppressLint("StaticFieldLeak")
object ThreatRepository {

    private var prefs: SharedPreferences? = null
    private val repoScope = CoroutineScope(Dispatchers.IO)

    private val _threats = MutableStateFlow<List<ThreatLog>>(emptyList())
    val threatsFlow: StateFlow<List<ThreatLog>> = _threats.asStateFlow()

    private val _threatCount = MutableStateFlow(0)
    val threatCountFlow: StateFlow<Int> = _threatCount.asStateFlow()

    /**
     * 🚨 THE PERSISTENCE INJECTOR
     * Call this exactly once in your Application class or MainActivity onCreate.
     */
    fun initialize(context: Context) {
        if (prefs != null) return
        prefs = context.getSharedPreferences("goprivate_threat_vault", Context.MODE_PRIVATE)
        loadFromDisk()
    }

    /**
     * Adds a new threat and asynchronously commits it to the physical flash storage.
     */
    fun addThreat(
        appName: String,
        packageName: String,
        threatType: String,
        riskScore: Float
    ) {
        val newThreat = ThreatLog(
            appName = appName,
            packageName = packageName,
            threatType = threatType,
            riskScore = riskScore,
            timestamp = System.currentTimeMillis() // 🚨 Ensure exact time is logged
        )

        // 1. Thread-safe atomic update for the UI
        _threats.update { currentList ->
            val updatedList = currentList.toMutableList()
            updatedList.add(0, newThreat)
            updatedList.take(50) // Keep only the last 50 to prevent disk bloat
        }

        _threatCount.update { it + 1 }

        // 2. Save to Disk in the background so we never freeze the ML Engine
        repoScope.launch {
            saveToDisk()
        }
    }

    fun getTotalThreatsBlocked(): Int = _threatCount.value

    fun clearHistory() {
        _threats.value = emptyList()
        _threatCount.value = 0
        repoScope.launch {
            prefs?.edit(commit = true) { clear() }
        }
    }

    // --- DISK I/O (No JSON Library Required) ---

    private fun saveToDisk() {
        val currentThreats = _threats.value
        // 🚨 CHRONOLOGICAL FIX: Save the exact timestamp to disk
        val serializedSet = currentThreats.map {
            "${it.appName}|||${it.packageName}|||${it.threatType}|||${it.riskScore}|||${it.timestamp}"
        }.toSet()

        prefs?.edit {
            putStringSet("threat_list", serializedSet)
            putInt("total_threat_count", _threatCount.value)
        }
    }

    private fun loadFromDisk() {
        val savedCount = prefs?.getInt("total_threat_count", 0) ?: 0
        val serializedSet = prefs?.getStringSet("threat_list", emptySet()) ?: emptySet()

        val loadedThreats = serializedSet.mapNotNull { rawString ->
            try {
                val parts = rawString.split("|||")
                if (parts.size == 5) {
                    ThreatLog(
                        appName = parts[0],
                        packageName = parts[1], // Previously called 'target'
                        threatType = parts[2],
                        riskScore = parts[3].toFloat(),
                        timestamp = parts[4].toLong() // 🚨 Restore exact time
                    )
                } else null
            } catch (e: Exception) { null }
        }

        _threatCount.value = savedCount
        // 🚨 CHRONOLOGICAL FIX: Sets scramble data. We must sort it by time manually after loading.
        _threats.value = loadedThreats.sortedByDescending { it.timestamp }
    }
}