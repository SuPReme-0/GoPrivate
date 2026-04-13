@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.viewmodels

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.goprivate.app.core.services.AppScannerService
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.model.AppScanResult
import com.goprivate.app.data.model.ScanState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScannerViewModel(application: Application) : AndroidViewModel(application) {

    private val packageManager = application.packageManager
    private val diskCache: SharedPreferences = application.getSharedPreferences("goprivate_forensic_cache", Context.MODE_PRIVATE)

    private val _allApps = MutableStateFlow<List<AppScanResult>>(emptyList())

    private val _scanningPackage = MutableStateFlow<String?>(null)
    val scanningPackageFlow: StateFlow<String?> = _scanningPackage.asStateFlow()

    private val _scanState = MutableStateFlow(ScanState())
    val scanStateFlow: StateFlow<ScanState> = _scanState.asStateFlow()

    private val _selectedApp = MutableStateFlow<AppScanResult?>(null)
    val selectedAppFlow: StateFlow<AppScanResult?> = _selectedApp.asStateFlow()

    private val _terminalLogs = MutableSharedFlow<String>(replay = 50)
    val terminalLogsFlow: SharedFlow<String> = _terminalLogs.asSharedFlow()

    private val _currentTextQuery = MutableStateFlow("")
    private val _currentRiskFilter = MutableStateFlow("ALL")

    // 🚨 RECEIVER 1: The ML Scan Listener
    private val scanReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "com.goprivate.app.SCAN_PROGRESS" -> handleScanProgress(intent)
                "com.goprivate.app.APP_SCANNED_RESULT" -> handleAppScannedResult(intent)
            }
        }
    }

    // 🚨 RECEIVER 2: The OS Purge Listener (Instantly removes uninstalled apps)
    private val packageRemovedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_PACKAGE_REMOVED) {
                val packageName = intent.data?.schemeSpecificPart ?: return

                // 🚨 OS UPDATE FIX: Ignore broadcasts caused by the Google Play Store updating apps
                val isUpdating = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

                // Only trigger the purge if it is a true, manual uninstallation
                if (!isUpdating) {
                    handleAppPurged(packageName)
                }
            }
        }
    }

    init {
        // Register Scan Receiver
        val filter = IntentFilter().apply {
            addAction("com.goprivate.app.SCAN_PROGRESS")
            addAction("com.goprivate.app.APP_SCANNED_RESULT")
        }
        // 🚨 ANDROID 14 FIX: Using RECEIVER_EXPORTED ensures global implicit broadcasts from the Service are not dropped
        ContextCompat.registerReceiver(application, scanReceiver, filter, ContextCompat.RECEIVER_EXPORTED)

        // Register OS Package Purge Receiver
        val pkgFilter = IntentFilter(Intent.ACTION_PACKAGE_REMOVED).apply {
            addDataScheme("package")
        }
        application.registerReceiver(packageRemovedReceiver, pkgFilter)
    }

    private fun handleScanProgress(intent: Intent) {
        val isScanning = intent.getBooleanExtra("isScanning", false)
        val progress = intent.getIntExtra("progress", 0)
        val scannedApps = intent.getIntExtra("scannedApps", 0)
        val totalApps = intent.getIntExtra("totalApps", 0)
        val threatsFound = intent.getIntExtra("threatsFound", 0)

        _scanState.update {
            it.copy(
                isScanning = isScanning,
                progress = progress,
                scannedApps = scannedApps,
                totalApps = totalApps,
                threatsFound = threatsFound
            )
        }

        if (!isScanning && progress == 100) {
            _scanningPackage.value = null
        }
    }

    private fun handleAppScannedResult(intent: Intent) {
        val packageName = intent.getStringExtra("packageName") ?: return

        val savedData = diskCache.getString(packageName, null) ?: return
        val parts = savedData.split("|")
        if (parts.size < 4) return

        val riskScore = parts[0].toFloatOrNull() ?: 0f
        val scanTimestamp = parts[1].toLongOrNull() ?: 0L
        val isIsolated = parts[2].toBooleanStrictOrNull() ?: false
        val feats = parts[3]
        val features = if (feats.isNotEmpty()) feats.split(";;;") else emptyList()

        _allApps.update { currentList ->
            currentList.map { app ->
                if (app.packageName == packageName) {
                    val updatedApp = app.copy(
                        riskScore = riskScore,
                        scanTimestamp = scanTimestamp,
                        activeThreatFeatures = features,
                        isIsolated = isIsolated
                    )
                    if (_selectedApp.value?.packageName == packageName) {
                        _selectedApp.value = updatedApp
                    }
                    updatedApp
                } else app
            }
        }
    }

    // 🚨 PURGE PROTOCOL: Cleans up the matrix automatically
    private fun handleAppPurged(packageName: String) {
        diskCache.edit { remove(packageName) }

        _allApps.update { currentList ->
            currentList.filter { it.packageName != packageName }
        }

        if (_selectedApp.value?.packageName == packageName) {
            _selectedApp.value = null
        }

        logToTerminal("> 🗑️ OS CONFIRM: $packageName purged from device storage.")
    }

    val displayedAppsFlow: StateFlow<List<AppScanResult>> = combine(
        _allApps,
        _currentTextQuery,
        _currentRiskFilter
    ) { apps, query, riskLevel ->
        var filteredList = apps

        if (query.isNotBlank()) {
            filteredList = filteredList.filter {
                it.appName.contains(query, ignoreCase = true) ||
                        it.packageName.contains(query, ignoreCase = true)
            }
        }

        filteredList = when (riskLevel) {
            "MALICIOUS" -> filteredList.filter { it.scanTimestamp != 0L && it.riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD }
            "SUSPICIOUS" -> filteredList.filter { it.scanTimestamp != 0L && it.riskScore >= 0.4f && it.riskScore < EngineBStaticManager.MALICIOUS_THRESHOLD }
            "SAFE" -> filteredList.filter { it.scanTimestamp != 0L && it.riskScore < 0.4f }
            else -> filteredList
        }

        filteredList
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private fun logToTerminal(message: String) {
        _terminalLogs.tryEmit(message)
    }

    private fun hasQueryAllPackagesPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(getApplication(), android.Manifest.permission.QUERY_ALL_PACKAGES) == PackageManager.PERMISSION_GRANTED
        } else true
    }

    fun initializeDashboard() {
        if (_allApps.value.isEmpty()) {
            if (hasQueryAllPackagesPermission()) refreshAppList()
            else logToTerminal("❌ QUERY_ALL_PACKAGES permission missing. Cannot list apps.")
        }
    }

    fun refreshAppList() {
        viewModelScope.launch(Dispatchers.IO) {
            withContext(NonCancellable) {
                logToTerminal("> INITIATING SYSTEM ENUMERATION...")

                val currentAppsMap = _allApps.value.associateBy { it.packageName }

                // 🚨 SDK 33+ COMPLIANCE
                val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
                } else {
                    packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                }

                val activePackageNames = packages.map { it.packageName }.toSet()

                diskCache.edit {
                    diskCache.all.keys.forEach { cachedPkg ->
                        if (!activePackageNames.contains(cachedPkg)) {
                            remove(cachedPkg)
                        }
                    }
                }

                val apps = packages.mapNotNull { pkg ->
                    packageManager.getLaunchIntentForPackage(pkg.packageName)
                        ?: return@mapNotNull null

                    val name = pkg.applicationInfo?.loadLabel(packageManager)?.toString() ?: return@mapNotNull null

                    var cachedScore = 0f
                    var cachedTime = 0L
                    var cachedIsolated = false
                    var cachedFeatures = emptyList<String>()

                    val savedData = diskCache.getString(pkg.packageName, null)
                    if (savedData != null) {
                        val parts = savedData.split("|")
                        if (parts.size >= 4) {
                            cachedScore = parts[0].toFloatOrNull() ?: 0f
                            cachedTime = parts[1].toLongOrNull() ?: 0L
                            cachedIsolated = parts[2].toBooleanStrictOrNull() ?: false
                            val feats = parts[3]
                            cachedFeatures = if (feats.isNotEmpty()) feats.split(";;;") else emptyList()
                        }
                    } else {
                        val existingData = currentAppsMap[pkg.packageName]
                        if (existingData != null) {
                            cachedScore = existingData.riskScore
                            cachedTime = existingData.scanTimestamp
                            cachedIsolated = existingData.isIsolated
                            cachedFeatures = existingData.activeThreatFeatures
                        }
                    }

                    AppScanResult(
                        packageName = pkg.packageName,
                        appName = name,
                        permissions = pkg.requestedPermissions?.toList() ?: emptyList(),
                        riskScore = cachedScore,
                        scanTimestamp = cachedTime,
                        activeThreatFeatures = cachedFeatures,
                        isIsolated = cachedIsolated
                    )
                }.sortedBy { it.appName }

                _allApps.value = apps
                _scanState.update { it.copy(totalApps = apps.size) }
                logToTerminal("> ENUMERATION COMPLETE: ${apps.size} user apps loaded from cache.\n")
            }
        }
    }

    fun filterByText(query: String) {
        _currentTextQuery.value = query
    }

    fun filterByRisk(riskLevel: String) {
        _currentRiskFilter.value = riskLevel
    }

    fun scanSingleApp(packageName: String) {
        if (_scanState.value.isScanning) {
            logToTerminal("⚠️ Engine is currently busy with another scan.")
            return
        }

        logToTerminal("\n=== DELEGATING MANUAL AUDIT TO IMMORTAL OS SERVICE ===")

        // 🚨 GLITCH FIX: Ensure totalApps = 1 so the UI math doesn't drop to 0/0.
        _scanState.update { it.copy(isScanning = true, progress = 0, scannedApps = 0, totalApps = 1) }
        _scanningPackage.value = packageName

        try {
            val serviceIntent = Intent(getApplication(), AppScannerService::class.java).apply {
                action = AppScannerService.ACTION_START_SINGLE_SCAN
                putExtra(AppScannerService.EXTRA_PACKAGE_NAME, packageName)
            }
            ContextCompat.startForegroundService(getApplication(), serviceIntent)
        } catch (e: Exception) {
            logToTerminal("❌ Failed to start Immortal Scanner Service: ${e.message}")
            _scanState.update { it.copy(isScanning = false) }
            _scanningPackage.value = null
        }
    }

    fun startFullSystemScan() {
        if (_scanState.value.isScanning) return
        logToTerminal("\n=== DELEGATING BATCH AUDIT TO IMMORTAL OS SERVICE ===")

        val targetCount = _allApps.value.size
        _scanState.update { it.copy(isScanning = true, progress = 0, scannedApps = 0, totalApps = targetCount) }

        try {
            val serviceIntent = Intent(getApplication(), AppScannerService::class.java).apply {
                action = AppScannerService.ACTION_START_BATCH_SCAN
            }
            ContextCompat.startForegroundService(getApplication(), serviceIntent)
        } catch (e: Exception) {
            logToTerminal("❌ Failed to start Immortal Scanner Service: ${e.message}")
        }
    }

    fun selectAppForDetails(app: AppScanResult) {
        _selectedApp.value = app
    }

    fun clearSelectedApp() {
        _selectedApp.value = null
    }

    // 🚨 TWO-WAY QUARANTINE PROTOCOL
    fun toggleAppIsolation(packageName: String) {
        val app = _allApps.value.find { it.packageName == packageName } ?: return
        val newState = !app.isIsolated // Toggle the state

        // Save state to SSD
        val featureString = app.activeThreatFeatures.joinToString(";;;")
        val serializedData = "${app.riskScore}|${app.scanTimestamp}|$newState|$featureString"
        diskCache.edit { putString(packageName, serializedData) }

        // Update RAM and flow to trigger UI repaint
        _allApps.update { currentList ->
            currentList.map {
                if (it.packageName == packageName) {
                    val updatedApp = it.copy(isIsolated = newState)
                    if (_selectedApp.value?.packageName == packageName) {
                        _selectedApp.value = updatedApp
                    }
                    updatedApp
                } else it
            }
        }

        // 🚨 EXPLICIT BROADCAST FIX: Forces Android 14 to deliver the command to the VPN
        val intent = Intent("ACTION_UPDATE_QUARANTINE").apply {
            setPackage(getApplication<Application>().packageName) // Explicit routing
            putExtra("PACKAGE_NAME", packageName)
            putExtra("IS_ISOLATED", newState)
        }
        getApplication<Application>().sendBroadcast(intent)

        if (newState) {
            logToTerminal("> 🛡️ QUARANTINE ENGAGED: $packageName network access severed.")
        } else {
            logToTerminal("> 🟢 QUARANTINE LIFTED: $packageName network access restored.")
        }
    }

    fun generateForensicReport(onReportReady: (String) -> Unit) {
        viewModelScope.launch(Dispatchers.Default) {
            val apps = _allApps.value
            val sb = StringBuilder()

            sb.append("===================================================\n")
            sb.append("GoPrivate ML Firewall - System Endpoint Audit\n")
            sb.append("Timestamp: ${java.util.Date()}\n")
            sb.append("Total Modules Scanned: ${apps.count { it.scanTimestamp > 0L }}\n")
            sb.append("===================================================\n\n")

            val malicious = apps.filter { it.riskScore >= EngineBStaticManager.MALICIOUS_THRESHOLD }
            val suspicious = apps.filter { it.riskScore >= 0.4f && it.riskScore < EngineBStaticManager.MALICIOUS_THRESHOLD }

            sb.append("[ CRITICAL THREATS DETECTED: ${malicious.size} ]\n")
            sb.append("---------------------------------------------------\n")
            malicious.sortedByDescending { it.riskScore }.forEach { app ->
                sb.append("[!] ${app.appName} (${app.packageName})\n")
                sb.append("    Risk Score: ${(app.riskScore * 100).toInt()}%\n")
                if (app.isIsolated) sb.append("    Status: [ QUARANTINED ]\n")
                if (app.activeThreatFeatures.isNotEmpty()) {
                    sb.append("    Vectors Identified: \n")
                    app.activeThreatFeatures.take(10).forEach { vector ->
                        sb.append("      - $vector\n")
                    }
                }
                sb.append("\n")
            }

            sb.append("\n[ SUSPICIOUS MODULES: ${suspicious.size} ]\n")
            sb.append("---------------------------------------------------\n")
            suspicious.sortedByDescending { it.riskScore }.forEach { app ->
                sb.append("[?] ${app.appName} (${app.packageName})\n")
                sb.append("    Risk Score: ${(app.riskScore * 100).toInt()}%\n")
                if (app.isIsolated) sb.append("    Status: [ QUARANTINED ]\n\n") else sb.append("\n")
            }

            sb.append("\n===================================================\n")
            sb.append("Report Compiled by Engine B (GoPrivate XAI Core)\n")
            sb.append("===================================================\n")

            withContext(Dispatchers.Main) {
                onReportReady(sb.toString())
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        try {
            getApplication<Application>().unregisterReceiver(scanReceiver)
            getApplication<Application>().unregisterReceiver(packageRemovedReceiver)
        } catch (e: Exception) {
            Log.e("ScannerViewModel", "Receiver already unregistered", e)
        }
    }
}

class ScannerViewModelFactory(private val application: Application) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(ScannerViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return ScannerViewModel(application) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}