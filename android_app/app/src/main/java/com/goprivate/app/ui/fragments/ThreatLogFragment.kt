@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.fragments

import android.annotation.SuppressLint
import android.os.Bundle
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
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.goprivate.app.R
import com.goprivate.app.data.model.ThreatLog
import com.goprivate.app.databinding.FragmentThreatLogBinding
import com.goprivate.app.ui.adapters.ThreatLogAdapter
import com.goprivate.app.ui.viewmodels.ThreatLogViewModel
import com.goprivate.app.ui.viewmodels.ThreatLogViewModelFactory
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.core.graphics.toColorInt

class ThreatLogFragment : Fragment() {

    private var _binding: FragmentThreatLogBinding? = null
    private val binding get() = _binding!!

    private val viewModel: ThreatLogViewModel by viewModels {
        ThreatLogViewModelFactory(requireActivity().application)
    }

    // 🚨 TRI-CORE ADAPTERS: One for each engine stream
    private lateinit var adapterEngineA: ThreatLogAdapter
    private lateinit var adapterEngineB: ThreatLogAdapter
    private lateinit var adapterEngineC: ThreatLogAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentThreatLogBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupUI()
        setupRecyclerViews()
        observeViewModel()
    }

    private fun setupUI() {
        // 🚨 RISK FILTER SYNC: Perfectly maps the UI Chips to the ViewModel Enum
        binding.filterChips.setOnCheckedStateChangeListener { _, checkedIds ->
            val selectedId = checkedIds.firstOrNull() ?: R.id.filter_all

            when (selectedId) {
                R.id.filter_all -> viewModel.setFilter(ThreatLogViewModel.RiskFilter.ALL)
                R.id.filter_malicious -> viewModel.setFilter(ThreatLogViewModel.RiskFilter.MALICIOUS)
                R.id.filter_suspicious -> viewModel.setFilter(ThreatLogViewModel.RiskFilter.SUSPICIOUS)
                R.id.filter_safe -> viewModel.setFilter(ThreatLogViewModel.RiskFilter.SAFE)
            }
        }

        binding.fabClearHistory.setOnClickListener {
            MaterialAlertDialogBuilder(requireContext(), R.style.Theme_MaterialComponents_DayNight_Dialog_Alert)
                .setTitle("⚠️ INITIATE QUARANTINE PURGE?")
                .setMessage("This action will permanently vaporize all forensic data of blocked malware, trackers, and network hazards. This action is irreversible.")
                .setPositiveButton("[ PURGE ]") { dialog, _ ->
                    viewModel.clearHistory()
                    binding.forensicDetailsPanel.visibility = View.GONE
                    dialog.dismiss()
                }
                .setNegativeButton("CANCEL") { dialog, _ ->
                    dialog.dismiss()
                }
                .show()
        }

        binding.forensicDetailsPanel.setOnClickListener {
            binding.forensicDetailsPanel.visibility = View.GONE
        }
    }

    private fun setupRecyclerViews() {
        // Instantiate the 3 separate adapters
        adapterEngineA = ThreatLogAdapter { showForensicDetails(it) }
        adapterEngineB = ThreatLogAdapter { showForensicDetails(it) }
        adapterEngineC = ThreatLogAdapter { showForensicDetails(it) }

        // Bind them to their respective physical RecyclerViews
        binding.recyclerEngineA.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = adapterEngineA
            setHasFixedSize(true)
            isNestedScrollingEnabled = false
        }

        binding.recyclerEngineB.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = adapterEngineB
            setHasFixedSize(true)
            isNestedScrollingEnabled = false
        }

        binding.recyclerEngineC.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = adapterEngineC
            setHasFixedSize(true)
            isNestedScrollingEnabled = false
        }
    }

    @SuppressLint("SetTextI18n")
    private fun showForensicDetails(threat: ThreatLog) {
        binding.forensicDetailsPanel.visibility = View.VISIBLE

        binding.threatNameDetail.text = threat.appName
        binding.threatTargetDetail.text = threat.packageName

        val formatter = SimpleDateFormat("MMM dd, yyyy - HH:mm:ss z", Locale.getDefault())
        binding.threatTimeDetail.text = "Logged: ${formatter.format(Date(threat.timestamp))}"

        val riskScore = threat.riskScore
        val percentage = (riskScore * 100).toInt()

        val engineID: String
        val severityClass: String
        val colorValue: Int

        // 🚨 SEVERITY & COLOR ROUTING
        when {
            threat.threatType.contains("Network", ignoreCase = true) || threat.threatType.contains("C2", ignoreCase = true) || threat.threatType.contains("Packet", ignoreCase = true) -> {
                engineID = "[ ENGINE A : NET_SHIELD ]"
                severityClass = if (riskScore >= 0.75f) "ACTIVE BOTNET DROPPED" else "COVERT TELEMETRY BLOCKED"
                colorValue = ContextCompat.getColor(requireContext(), if (riskScore >= 0.75f) R.color.alert_red_primary else R.color.neon_cyan_primary)
            }
            threat.threatType.contains("Privacy", ignoreCase = true) || threat.threatType.contains("Sharing", ignoreCase = true) || threat.threatType.contains("Data", ignoreCase = true) || threat.threatType.contains("Analyzer", ignoreCase = true) -> {
                engineID = "[ ENGINE C : NLP_AUDITOR ]"
                severityClass = if (riskScore >= 0.75f) "ILLEGAL DATA BROKERAGE" else "INVASIVE CLAUSES DETECTED"
                colorValue = "#FFAA00".toColorInt() // Always Amber for NLP
            }
            else -> {
                engineID = "[ ENGINE B : XAI_STATIC ]"
                severityClass = if (riskScore >= 0.75f) "CRITICAL MALWARE PAYLOAD" else "UNVERIFIED SIDELOAD"
                colorValue = ContextCompat.getColor(requireContext(), if (riskScore >= 0.75f) R.color.alert_red_primary else R.color.neon_cyan_primary)
            }
        }

        binding.threatEngineDetail.text = engineID
        binding.threatEngineDetail.setTextColor(ContextCompat.getColor(requireContext(), R.color.neon_cyan_primary))

        binding.threatSeverityDetail.text = "> SEVERITY: $severityClass"
        binding.threatSeverityDetail.setTextColor(colorValue)

        binding.threatScoreDetail.text = "AI_CONFIDENCE: $percentage%"
        binding.threatScoreDetail.setTextColor(colorValue)

        // Prepares the container for the future XAI clause injection
        binding.threatVectorLog.text = "[ TRINITY MATRIX LOG ]\n" +
                "> Intercepted Type: ${threat.threatType}\n" +
                "> Target Vector: ${threat.packageName}\n" +
                "> System Action: AUTO-QUARANTINE ENFORCED\n" +
                "> Forensics: (Awaiting Schema Upgrade...)"
    }

    @SuppressLint("SetTextI18n")
    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {

                // =====================================================================
                // 🚨 TRI-CORE OBSERVATION PIPELINE
                // Listens to 3 separate StateFlows and syncs empty states independently.
                // =====================================================================

                launch {
                    viewModel.engineAThreats.collectLatest { threats ->
                        adapterEngineA.submitList(threats)
                        binding.emptyStateEngineA.visibility = if (threats.isEmpty()) View.VISIBLE else View.GONE
                        binding.recyclerEngineA.visibility = if (threats.isEmpty()) View.GONE else View.VISIBLE
                    }
                }

                launch {
                    viewModel.engineBThreats.collectLatest { threats ->
                        adapterEngineB.submitList(threats)
                        binding.emptyStateEngineB.visibility = if (threats.isEmpty()) View.VISIBLE else View.GONE
                        binding.recyclerEngineB.visibility = if (threats.isEmpty()) View.GONE else View.VISIBLE
                    }
                }

                launch {
                    viewModel.engineCThreats.collectLatest { threats ->
                        adapterEngineC.submitList(threats)
                        binding.emptyStateEngineC.visibility = if (threats.isEmpty()) View.VISIBLE else View.GONE
                        binding.recyclerEngineC.visibility = if (threats.isEmpty()) View.GONE else View.VISIBLE
                    }
                }

                // =====================================================================
                // 🚨 GLOBAL HUD SYNCHRONIZATION
                // Keeps the top 3 counters accurate regardless of the active chip filter.
                // =====================================================================
                launch {
                    viewModel.allThreatsFlow.collectLatest { allThreats ->
                        val engineACount = allThreats.count {
                            it.threatType.contains("Network", true) ||
                                    it.threatType.contains("C2", true) ||
                                    it.threatType.contains("Packet", true)
                        }

                        val engineBCount = allThreats.count {
                            it.threatType.contains("Signature", true) ||
                                    it.threatType.contains("Sideload", true) ||
                                    it.threatType.contains("API", true) ||
                                    it.threatType.contains("Permissions", true)
                        }

                        val engineCCount = allThreats.count {
                            it.threatType.contains("Privacy", true) ||
                                    it.threatType.contains("Sharing", true) ||
                                    it.threatType.contains("Data", true) ||
                                    it.threatType.contains("Analyzer", true)
                        }

                        binding.engineACount.text = engineACount.toString()
                        binding.engineBCount.text = engineBCount.toString()
                        binding.engineCCount.text = engineCCount.toString()
                    }
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}