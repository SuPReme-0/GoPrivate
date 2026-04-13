@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.fragments

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.goprivate.app.R
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.data.ml.EngineANetworkManager
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.model.AppScanResult
import com.goprivate.app.databinding.FragmentScannerBinding
import com.goprivate.app.ui.adapters.AppScannerAdapter
import com.goprivate.app.ui.viewmodels.ScannerViewModel
import com.goprivate.app.ui.viewmodels.ScannerViewModelFactory
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ScannerFragment : Fragment() {

    private var _binding: FragmentScannerBinding? = null
    private val binding get() = _binding!!

    private var isVpnActive = false

    private val viewModel: ScannerViewModel by viewModels {
        ScannerViewModelFactory(requireActivity().application)
    }

    private lateinit var appAdapter: AppScannerAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentScannerBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setupRecyclerView()
        observeViewModel()
        setupUI()

        viewModel.initializeDashboard()
    }

    private fun setupRecyclerView() {
        appAdapter = AppScannerAdapter(
            onItemClick = { app -> viewModel.selectAppForDetails(app) },
            onScanClick = { app ->
                if (EngineBStaticManager.isReady()) {
                    viewModel.scanSingleApp(app.packageName)
                } else {
                    appendToTerminal("⚠️ SYSTEM ERR: Engine B offline. Cannot scan ${app.appName}.")
                }
            }
        )

        binding.appsRecyclerView.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = appAdapter
            setHasFixedSize(true)
        }
    }

    private fun setupUI() {
        binding.searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                viewModel.filterByText(s?.toString() ?: "")
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        binding.scanButton.setOnClickListener {
            if (!EngineBStaticManager.isReady()) {
                appendToTerminal("⚠️ SYSTEM ERR: Engine B is offline. Check Storage Permissions in Settings.")
                return@setOnClickListener
            }
            TelemetryManager.logToTerminal("SCANNER", "Initiating Full-System Execution Protocol...")
            viewModel.startFullSystemScan()
        }

        binding.refreshButton.setOnClickListener {
            TelemetryManager.logToTerminal("SCANNER", "Reloading OS Application Directory...")
            viewModel.refreshAppList()
        }

        binding.exportReportButton.setOnClickListener {
            appendToTerminal("> Compiling Forensic Audit Report...")
            viewModel.generateForensicReport { reportText ->
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, reportText)
                    type = "text/plain"
                }
                val shareIntent = Intent.createChooser(sendIntent, "Export GoPrivate Forensics")
                startActivity(shareIntent)
                appendToTerminal("> Report generated and exported to OS handler.")
            }
        }

        binding.detailsPanel.setOnClickListener {
            viewModel.clearSelectedApp()
        }
    }

    @SuppressLint("SetTextI18n")
    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {

                // 🚨 VPN STATE LISTENER
                launch {
                    EngineANetworkManager.vpnActiveFlow.collect { active ->
                        isVpnActive = active
                        viewModel.selectedAppFlow.value?.let { showAppDetails(it) }
                    }
                }

                launch {
                    viewModel.displayedAppsFlow.collectLatest { apps ->
                        appAdapter.submitList(apps)
                    }
                }

                launch {
                    viewModel.selectedAppFlow.collectLatest { app ->
                        if (app != null) {
                            showAppDetails(app)
                        } else {
                            binding.detailsPanel.visibility = View.GONE
                        }
                    }
                }

                launch {
                    binding.terminalOutputText.text = ""
                    viewModel.terminalLogsFlow.collect { logMessage ->
                        if (logMessage.isNotEmpty()) appendToTerminal(logMessage)
                    }
                }

                launch {
                    viewModel.scanningPackageFlow.collectLatest { packageName ->
                        appAdapter.setScanningPackage(packageName)
                    }
                }

                launch {
                    combine(
                        viewModel.scanStateFlow,
                        EngineBStaticManager.scanProgressFlow
                    ) { state, engineStatus ->
                        Pair(state, engineStatus)
                    }.collect { (state, engineStatus) ->
                        binding.scanProgressIndicator.progress = state.progress
                        binding.scanButton.isEnabled = !state.isScanning
                        binding.scanButton.alpha = if (state.isScanning) 0.5f else 1.0f

                        if (state.isScanning) {
                            if (engineStatus.isNotEmpty()) {
                                binding.scanStatusText.text = "EXEC_SCAN: ${state.scannedApps}/${state.totalApps} | $engineStatus"
                                binding.scanStatusText.setTextColor(ContextCompat.getColor(requireContext(), R.color.neon_green_primary))
                            } else {
                                binding.scanStatusText.text = "EXEC_SCAN: ${state.scannedApps}/${state.totalApps} | Processing..."
                                binding.scanStatusText.setTextColor(ContextCompat.getColor(requireContext(), R.color.neon_green_primary))
                            }
                        } else {
                            if (state.totalApps > 0 && state.progress == 100) {
                                binding.scanStatusText.text = "PROTOCOL_COMPLETE // Threats: ${state.threatsFound}"
                                binding.scanStatusText.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe))
                            } else {
                                binding.scanStatusText.text = "Status: STANDBY"
                                binding.scanStatusText.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
                            }
                        }
                    }
                }
            }
        }
    }

    @SuppressLint("SetTextI18n")
    private fun showAppDetails(app: AppScanResult) {
        binding.detailsPanel.visibility = View.VISIBLE
        binding.appNameDetail.text = app.appName
        binding.packageNameDetail.text = app.packageName

        // ==========================================
        // 1. UPDATE FORENSIC TEXT & STATUS PANELS
        // ==========================================
        if (app.scanTimestamp == 0L) {
            binding.trinityStaticScore.text = "--"
            binding.trinityStaticScore.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
            binding.trinityPrivacyState.text = "[ WAIT ]"
            binding.sideloadTag.visibility = View.GONE
            binding.featureLogDetail.text = "> Forensic Telemetry Data Awaiting Execution..."

            if (!isVpnActive) {
                binding.trinityNetState.text = "VPN OFFLINE"
                binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
            } else {
                binding.trinityNetState.text = "[ WAIT ]"
                binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
            }
        } else {
            val percentage = (app.riskScore * 100).toInt()
            binding.trinityStaticScore.text = "$percentage%"

            val colorRes = when {
                app.riskScore < EngineBStaticManager.MALICIOUS_THRESHOLD / 2 -> R.color.status_safe
                app.riskScore < EngineBStaticManager.MALICIOUS_THRESHOLD -> R.color.status_suspicious
                else -> R.color.status_malicious
            }
            binding.trinityStaticScore.setTextColor(ContextCompat.getColor(requireContext(), colorRes))

            val isSideloaded = app.activeThreatFeatures.any { it.contains("Unverified Sideload") }
            binding.sideloadTag.visibility = if (isSideloaded) View.VISIBLE else View.GONE

            val isPrivacyInvasive = app.activeThreatFeatures.any { it.contains("Covert") || it.contains("Harvesting") || it.contains("Location") || it.contains("Screen Overlay") }
            if (isPrivacyInvasive) {
                binding.trinityPrivacyState.text = "INVASIVE"
                binding.trinityPrivacyState.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_malicious))
            } else {
                binding.trinityPrivacyState.text = "SAFE"
                binding.trinityPrivacyState.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe))
            }

            if (!isVpnActive) {
                if (app.isIsolated) {
                    binding.trinityNetState.text = "QUARANTINE SUSPENDED"
                    binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
                } else {
                    binding.trinityNetState.text = "UNPROTECTED"
                    binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
                }
            } else {
                if (app.isIsolated) {
                    binding.trinityNetState.text = "QUARANTINED"
                    binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.alert_red_primary))
                } else {
                    val hasNetRisk = app.activeThreatFeatures.any { it.contains("INTERNET", ignoreCase = true) } && app.riskScore >= 0.4f
                    if (hasNetRisk) {
                        binding.trinityNetState.text = "ACTIVE_C2"
                        binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_suspicious))
                    } else {
                        binding.trinityNetState.text = "CLEAN"
                        binding.trinityNetState.setTextColor(ContextCompat.getColor(requireContext(), R.color.neon_cyan_primary))
                    }
                }
            }

            val xaiReport = StringBuilder()
            val headers = app.activeThreatFeatures.filter { it.startsWith("STATUS:") || it.startsWith("Provenance:") || it.startsWith("Matrix") }
            headers.forEach { xaiReport.append("> $it\n") }
            xaiReport.append("\n")

            val permissions = app.activeThreatFeatures.filter { it.startsWith("permission::", ignoreCase = true) }
            val apis = app.activeThreatFeatures.filter { it.startsWith("apicalls::", ignoreCase = true) }
            val capabilities = app.activeThreatFeatures.filter { it.startsWith("> ") }

            if (capabilities.isNotEmpty()) {
                xaiReport.append("[ DETECTED CAPABILITIES ]\n")
                capabilities.forEach { xaiReport.append("$it\n") }
                xaiReport.append("\n")
            }

            if (permissions.isNotEmpty()) {
                xaiReport.append("[ 🛡️ REQUESTED PERMISSIONS ]\n")
                permissions.sorted().take(10).forEach { perm ->
                    val cleanPerm = perm.substringAfterLast('.').uppercase()
                    xaiReport.append("> $cleanPerm\n")
                }
                if (permissions.size > 10) xaiReport.append("> ... and ${permissions.size - 10} more.\n")
                xaiReport.append("\n")
            }

            if (apis.isNotEmpty()) {
                xaiReport.append("[ ⚙️ EXECUTED API CALLS ]\n")
                apis.sorted().take(10).forEach { api ->
                    val className = api.substringBefore("->").substringAfterLast('/').substringBefore(';')
                    val methodName = api.substringAfter("->").substringBefore('(')
                    xaiReport.append("> $className -> $methodName()\n")
                }
                if (apis.size > 10) xaiReport.append("> ... and ${apis.size - 10} more hidden vectors.\n")
            }

            if (capabilities.isEmpty() && apis.isEmpty() && headers.isEmpty()) {
                xaiReport.append("[ XAI FORENSICS ]\n> No advanced API vectors detected.\n> Binary integrity verified.")
            }

            binding.featureLogDetail.text = xaiReport.toString()
        }

        // ==========================================
        // 2. UNIVERSAL BUTTON STATE LOGIC
        // ==========================================

        // 🚨 TEXT WRAP FIX: Using a shorter string that universally fits
        if (!isVpnActive) {
            binding.isolateButton.text = "[ VPN OFF ]"
            binding.isolateButton.isEnabled = false
            binding.isolateButton.alpha = 0.5f
        } else if (app.scanTimestamp == 0L) {
            binding.isolateButton.text = "[ ISOLATE_NET ]"
            binding.isolateButton.isEnabled = false
            binding.isolateButton.alpha = 0.5f
        } else {
            if (app.isIsolated) {
                binding.isolateButton.text = "[ RESTORE_NET ]"
                binding.isolateButton.isEnabled = true
                binding.isolateButton.alpha = 1.0f
            } else {
                binding.isolateButton.text = "[ ISOLATE_NET ]"
                binding.isolateButton.isEnabled = true
                binding.isolateButton.alpha = 1.0f
            }
        }

        // ==========================================
        // 3. LISTENERS
        // ==========================================
        binding.uninstallButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_DELETE).apply {
                data = Uri.fromParts("package", app.packageName, null)
            }
            startActivity(intent)
        }

        binding.isolateButton.setOnClickListener {
            viewModel.toggleAppIsolation(app.packageName)
        }
    }

    private fun appendToTerminal(message: String) {
        val currentText = binding.terminalOutputText.text.toString()
        val lines = currentText.split("\n").filter { it.isNotBlank() }

        val keptLines = if (lines.size > 100) lines.takeLast(100) else lines

        val timeStamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val formattedMessage = if (message.startsWith("[")) message else "[$timeStamp] $message"

        val newText = keptLines.joinToString("\n") + "\n" + formattedMessage
        binding.terminalOutputText.text = newText

        binding.terminalScrollView.post {
            binding.terminalScrollView.fullScroll(View.FOCUS_DOWN)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}