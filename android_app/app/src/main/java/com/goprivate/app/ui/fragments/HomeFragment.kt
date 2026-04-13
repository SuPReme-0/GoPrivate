@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.fragments

import android.annotation.SuppressLint
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.SystemClock
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.github.mikephil.charting.data.Entry
import com.github.mikephil.charting.data.LineData
import com.github.mikephil.charting.data.LineDataSet
import com.goprivate.app.R
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.core.network.GoPrivateVpnService
import com.goprivate.app.data.model.NetworkDataPoint
import com.goprivate.app.databinding.FragmentHomeBinding
import com.goprivate.app.ui.viewmodels.HomeViewModel
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import java.net.NetworkInterface
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by viewModels()
    private var isVpnActive = false

    // Hardware clock debounce
    private var lastClickTime = 0L
    private val DEBOUNCE_MS = 2500L

    // Dedicated executor for blocking kernel calls
    private val tunnelCheckExecutor = Executors.newSingleThreadExecutor()

    // Jobs to cancel on destroy
    private var kernelMonitorJob: Job? = null
    private var resumeSyncJob: Job? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupUI()
        setupChart()
        observeViewModel()
        observeLiveTerminal()
    }

    override fun onResume() {
        super.onResume()
        // Cancel any previous sync job to avoid overlapping
        resumeSyncJob?.cancel()
        resumeSyncJob = lifecycleScope.launch(Dispatchers.IO) {
            val alive = isTunnelAlive()
            withContext(Dispatchers.Main) {
                if (!isAdded || lifecycle.currentState != Lifecycle.State.RESUMED) return@withContext
                // Don't interfere if we are inside debounce window
                if (SystemClock.elapsedRealtime() - lastClickTime < DEBOUNCE_MS) return@withContext
                if (isVpnActive != alive) {
                    TelemetryManager.logToTerminal("SYS", "Resync: VPN state = $alive")
                    updateVpnUiState(active = alive, isTransition = false)
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        // Cancel ongoing kernel monitor to avoid work when not visible
        kernelMonitorJob?.cancel()
        resumeSyncJob?.cancel()
    }

    /**
     * Thread‑safe, timeout‑enforced kernel check.
     * Must be called from a coroutine (Dispatchers.IO recommended).
     */
    private suspend fun isTunnelAlive(): Boolean = withContext(Dispatchers.IO) {
        try {
            withTimeoutOrNull(2000L) {
                val future = tunnelCheckExecutor.submit(Callable {
                    try {
                        val interfaces =
                            NetworkInterface.getNetworkInterfaces() ?: return@Callable false
                        // Convert Enumeration to Sequence and check condition
                        interfaces.asSequence().any { netInterface ->
                            netInterface.isUp && (netInterface.name == "tun0" || netInterface.name == "ppp0")
                        }
                    } catch (e: Exception) {
                        false
                    }
                })
                future.get(2, TimeUnit.SECONDS)
            } ?: false
        } catch (e: Exception) {
            false
        }
    }
    @SuppressLint("SetTextI18n")
    private fun setupUI() {
        binding.cyberRadar.setOnClickListener {
            // Guard: fragment not ready or already disabled
            if (!isAdded || lifecycle.currentState != Lifecycle.State.RESUMED) return@setOnClickListener
            if (!binding.cyberRadar.isEnabled) return@setOnClickListener

            val now = SystemClock.elapsedRealtime()
            if (now - lastClickTime < DEBOUNCE_MS) {
                TelemetryManager.logToTerminal("SYS", "⚠️ Safety lock active. Please wait.")
                return@setOnClickListener
            }
            lastClickTime = now
            binding.cyberRadar.isEnabled = false

            if (isVpnActive) {
                // Shutdown
                updateVpnUiState(active = false, isTransition = true)
                TelemetryManager.logToTerminal("SYS", "Severing hardline...")
                try {
                    val intent = Intent(requireContext(), GoPrivateVpnService::class.java).apply {
                        action = "ACTION_DISCONNECT_VPN"
                    }
                    requireContext().startService(intent)
                } catch (e: Exception) {
                    TelemetryManager.logToTerminal("ERR", "Stop failed: ${e.message}")
                }
                scheduleKernelPoll(targetActive = false)
            } else {
                // Startup
                updateVpnUiState(active = true, isTransition = true)
                TelemetryManager.logToTerminal("SYS", "Ignition sequence...")
                try {
                    val prepareIntent = VpnService.prepare(requireContext())
                    if (prepareIntent != null) {
                        startActivityForResult(prepareIntent, 1010)
                    } else {
                        startVpnService()
                    }
                } catch (e: Exception) {
                    TelemetryManager.logToTerminal("ERR", "VPN prepare failed: ${e.message}")
                    scheduleKernelPoll(targetActive = false)
                }
            }
        }

        binding.appsScannedCount.text = "0"
        binding.threatsBlockedCount.text = "0"
        binding.networkProtectedCount.text = "0.0 MB"
        binding.packetRateCount.text = "0 p/s"
    }

    private fun startVpnService() {
        try {
            val intent = Intent(requireContext(), GoPrivateVpnService::class.java).apply {
                action = "ACTION_START_VPN"
            }
            ContextCompat.startForegroundService(requireContext(), intent)
            TelemetryManager.logToTerminal("SYS", "Start command sent.")
            scheduleKernelPoll(targetActive = true)
        } catch (e: Exception) {
            TelemetryManager.logToTerminal("ERR", "Start failed: ${e.message}")
            scheduleKernelPoll(targetActive = false)
        }
    }

    /**
     * Polls the kernel until the desired tunnel state is reached, then unlocks the UI.
     * Uses a timeout (8 seconds) to avoid indefinite waiting.
     */
    private fun scheduleKernelPoll(targetActive: Boolean) {
        kernelMonitorJob?.cancel()
        kernelMonitorJob = lifecycleScope.launch(Dispatchers.IO) {
            delay(300) // brief settle time
            for (i in 0 until 32) { // 8 seconds max (32 * 250ms)
                if (!isAdded || lifecycle.currentState != Lifecycle.State.RESUMED) break
                if (isTunnelAlive() == targetActive) {
                    withContext(Dispatchers.Main) {
                        if (isAdded) {
                            binding.cyberRadar.isEnabled = true
                            updateVpnUiState(active = targetActive, isTransition = false)
                            TelemetryManager.logToTerminal("SYS", if (targetActive) "Tunnel active." else "Tunnel closed.")
                        }
                    }
                    return@launch
                }
                delay(250)
            }
            // Timeout fallback: force sync to current kernel state
            val finalState = isTunnelAlive()
            withContext(Dispatchers.Main) {
                if (isAdded) {
                    binding.cyberRadar.isEnabled = true
                    updateVpnUiState(active = finalState, isTransition = false)
                    TelemetryManager.logToTerminal("ERR", "Kernel poll timeout. Synced to: $finalState")
                }
            }
        }
    }

    @SuppressLint("SetTextI18n")
    private fun updateVpnUiState(active: Boolean, isTransition: Boolean) {
        if (isTransition) {
            binding.systemStatusSub.text = if (active) "[ INITIATING IGNITION... ]" else "[ SEVERING TUNNEL... ]"
            binding.systemStatusSub.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_primary))
            binding.packetRateCount.text = "0 p/s"
            binding.cyberRadar.alpha = 0.5f
            return
        }

        isVpnActive = active
        binding.cyberRadar.alpha = 1f
        if (active) {
            binding.systemStatusSub.text = "[ SYSTEM ACTIVE - VPN TUNNEL SECURE ]"
            binding.systemStatusSub.setTextColor(ContextCompat.getColor(requireContext(), R.color.neon_green_primary))
        } else {
            binding.systemStatusSub.text = "[ SYSTEM STANDBY - TUNNEL OFFLINE ]"
            binding.systemStatusSub.setTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_secondary))
            binding.packetRateCount.text = "0 p/s"
            // Clear the chart when VPN is off
            updateChart(emptyList())
        }
    }

    private fun setupChart() {
        val chart = binding.networkChart
        chart.apply {
            setTouchEnabled(true)
            isDragEnabled = true
            setScaleEnabled(true)
            setPinchZoom(false)
            description.isEnabled = false
            legend.isEnabled = false
            xAxis.setDrawGridLines(false)
            axisLeft.setDrawGridLines(false)
            axisRight.setDrawGridLines(false)
            xAxis.isEnabled = false
            axisLeft.isEnabled = false
            axisRight.isEnabled = false
            setNoDataText("[ AWAITING_NETWORK_TELEMETRY ]")
            setNoDataTextColor(ContextCompat.getColor(requireContext(), R.color.terminal_text_dim))
        }

        val dataSet = LineDataSet(emptyList(), "Packets/sec").apply {
            val cyberBlue = ContextCompat.getColor(requireContext(), R.color.neon_cyan_primary)
            color = cyberBlue
            setCircleColor(cyberBlue)
            lineWidth = 2f
            circleRadius = 2f
            setDrawFilled(true)
            fillColor = cyberBlue
            fillAlpha = 60
            mode = LineDataSet.Mode.CUBIC_BEZIER
            setDrawValues(false)
        }
        chart.data = LineData(dataSet)
        chart.invalidate()
    }

    @SuppressLint("SetTextI18n", "DefaultLocale")
    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collectLatest { state ->
                    binding.appsScannedCount.text = state.scannedCount.toString()
                    binding.threatsBlockedCount.text = state.blockedCount.toString()
                    binding.networkProtectedCount.text = String.format("%.1f MB", state.protectedMb)

                    val inTransition = SystemClock.elapsedRealtime() - lastClickTime < DEBOUNCE_MS
                    if (isVpnActive && !inTransition && binding.cyberRadar.isEnabled) {
                        binding.packetRateCount.text = "${state.packetRate.toInt()} p/s"
                        updateChart(state.networkData)
                    } else if (!isVpnActive) {
                        binding.packetRateCount.text = "0 p/s"
                    }
                }
            }
        }
    }

    private fun observeLiveTerminal() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                TelemetryManager.liveTerminalLogs.collectLatest { logMessage ->
                    val current = binding.terminalOutput.text.toString()
                    val lines = current.split("\n")
                    val kept = if (lines.size > 50) lines.takeLast(50) else lines
                    val newText = kept.joinToString("\n") + "\n" + logMessage
                    binding.terminalOutput.text = newText
                    binding.logScrollView.post {
                        binding.logScrollView.fullScroll(ScrollView.FOCUS_DOWN)
                    }
                }
            }
        }
    }

    private fun updateChart(data: List<NetworkDataPoint>) {
        val chart = binding.networkChart
        if (chart.data == null) return
        val entries = data.mapIndexed { idx, point -> Entry(idx.toFloat(), point.packetRate) }
        val dataSet = chart.data.getDataSetByIndex(0) as? LineDataSet
        dataSet?.values = entries
        chart.data.notifyDataChanged()
        chart.notifyDataSetChanged()
        chart.invalidate()
        if (entries.isNotEmpty()) {
            chart.moveViewToX(entries.size.toFloat())
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1010) {
            if (resultCode == android.app.Activity.RESULT_OK) {
                startVpnService()
            } else {
                Toast.makeText(requireContext(), "VPN Permission Denied", Toast.LENGTH_SHORT).show()
                TelemetryManager.logToTerminal("ERR", "VPN permission denied.")
                lastClickTime = 0L
                binding.cyberRadar.isEnabled = true
                updateVpnUiState(active = false, isTransition = false)
            }
        }
    }

    override fun onDestroyView() {
        tunnelCheckExecutor.shutdownNow()
        kernelMonitorJob?.cancel()
        resumeSyncJob?.cancel()
        _binding = null
        super.onDestroyView()
    }
}