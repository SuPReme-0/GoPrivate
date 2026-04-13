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
import com.goprivate.app.ui.viewmodels.ThreatLogViewModelFactory // 🚨 Imported directly from ViewModel file
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.core.graphics.toColorInt

class ThreatLogFragment : Fragment() {

    private var _binding: FragmentThreatLogBinding? = null
    private val binding get() = _binding!!

    // 🚨 FACTORY FIX: Uses the imported factory
    private val viewModel: ThreatLogViewModel by viewModels {
        ThreatLogViewModelFactory(requireActivity().application)
    }

    private lateinit var threatAdapter: ThreatLogAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentThreatLogBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupUI()
        setupRecyclerView()
        observeViewModel()
    }

    private fun setupUI() {
        binding.filterChips.setOnCheckedStateChangeListener { _, checkedIds ->
            val selectedId = checkedIds.firstOrNull() ?: R.id.filter_all

            // 🚨 ENGINE C FIX: Perfectly synced with ViewModel Enums
            when (selectedId) {
                R.id.filter_all -> viewModel.setFilter(ThreatLogViewModel.ThreatFilter.ALL)
                R.id.filter_critical -> viewModel.setFilter(ThreatLogViewModel.ThreatFilter.CRITICAL)
                R.id.filter_warnings -> viewModel.setFilter(ThreatLogViewModel.ThreatFilter.WARNING)
                R.id.filter_engine_a -> viewModel.setFilter(ThreatLogViewModel.ThreatFilter.ENGINE_A)
                R.id.filter_engine_b -> viewModel.setFilter(ThreatLogViewModel.ThreatFilter.ENGINE_B)
                R.id.filter_engine_c -> viewModel.setFilter(ThreatLogViewModel.ThreatFilter.ENGINE_C)
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

        // Dismiss the panel if the user taps it
        binding.forensicDetailsPanel.setOnClickListener {
            binding.forensicDetailsPanel.visibility = View.GONE
        }
    }

    private fun setupRecyclerView() {
        // 🚨 ADAPTER FIX: Passes the click listener to trigger the Holographic Modal
        threatAdapter = ThreatLogAdapter { selectedThreat ->
            showForensicDetails(selectedThreat)
        }

        binding.threatLogRecycler.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = threatAdapter
            setHasFixedSize(true)
        }
    }

    @SuppressLint("SetTextI18n")
    private fun showForensicDetails(threat: ThreatLog) {
        binding.forensicDetailsPanel.visibility = View.VISIBLE

        binding.threatNameDetail.text = threat.appName

        // 🚨 COMPILER FIX: Uses packageName instead of target
        binding.threatTargetDetail.text = threat.packageName

        val formatter = SimpleDateFormat("MMM dd, yyyy - HH:mm:ss z", Locale.getDefault())
        binding.threatTimeDetail.text = "Logged: ${formatter.format(Date(threat.timestamp))}"

        val riskScore = threat.riskScore
        val percentage = (riskScore * 100).toInt()

        val engineID: String
        val severityClass: String
        val colorValue: Int

        // 🚨 SEVERITY TRANSLATOR: Maps raw scores to actionable intelligence
        when {
            threat.threatType.contains("Network", ignoreCase = true) || threat.threatType.contains("C2", ignoreCase = true) -> {
                engineID = "[ ENGINE A : NET_SHIELD ]"
                severityClass = if (riskScore > 0.8f) "ACTIVE BOTNET CONNECTION DROPPED" else "COVERT TELEMETRY BLOCKED"
                colorValue = ContextCompat.getColor(requireContext(), if (riskScore > 0.8f) R.color.alert_red_primary else R.color.neon_cyan_primary)
            }
            threat.threatType.contains("Privacy", ignoreCase = true) || threat.threatType.contains("Sharing", ignoreCase = true) || threat.threatType.contains("Data", ignoreCase = true) -> {
                engineID = "[ ENGINE C : NLP_AUDITOR ]"
                severityClass = if (riskScore > 0.9f) "ILLEGAL DATA BROKERAGE DETECTED" else "INVASIVE EULA CLAUSES"
                colorValue = "#FFAA00".toColorInt() // 🚨 COLOR FIX: Forces Orange mathematically
            }
            else -> {
                engineID = "[ ENGINE B : XAI_STATIC ]"
                severityClass = if (riskScore > 0.8f) "CRITICAL MALWARE PAYLOAD" else "UNVERIFIED SIDELOAD HEURISTICS"
                colorValue = ContextCompat.getColor(requireContext(), if (riskScore > 0.8f) R.color.alert_red_primary else R.color.neon_cyan_primary)
            }
        }

        binding.threatEngineDetail.text = engineID
        binding.threatEngineDetail.setTextColor(ContextCompat.getColor(requireContext(), R.color.neon_cyan_primary))

        binding.threatSeverityDetail.text = "> SEVERITY: $severityClass"
        binding.threatSeverityDetail.setTextColor(colorValue)

        binding.threatScoreDetail.text = "AI_CONFIDENCE: $percentage%"
        binding.threatScoreDetail.setTextColor(colorValue)

        binding.threatVectorLog.text = "[ TRINITY MATRIX LOG ]\n" +
                "> Intercepted Type: ${threat.threatType}\n" +
                "> Target Vector: ${threat.packageName}\n" +
                "> System Action: HARD BLOCK ENFORCED"
    }

    @SuppressLint("SetTextI18n")
    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {

                // 1. Observe the Filtered List for the RecyclerView
                launch {
                    viewModel.threatsFlow.collectLatest { threats ->
                        threatAdapter.submitList(threats) {
                            if (threats.isNotEmpty()) {
                                binding.threatLogRecycler.scrollToPosition(0)
                            }
                        }

                        // Toggle Empty State UI
                        if (threats.isEmpty()) {
                            binding.emptyStateText.visibility = View.VISIBLE
                            binding.threatLogRecycler.visibility = View.GONE
                        } else {
                            binding.emptyStateText.visibility = View.GONE
                            binding.threatLogRecycler.visibility = View.VISIBLE
                        }
                    }
                }

                // 2. Observe the Global Stats for the Top Grid
                launch {
                    viewModel.allThreatsFlow.collectLatest { allThreats ->
                        val engineACount = allThreats.count { it.threatType.contains("Network", ignoreCase = true) || it.threatType.contains("C2", ignoreCase = true) }

                        val engineBCount = allThreats.count {
                            it.threatType.contains("Signature", ignoreCase = true) ||
                                    it.threatType.contains("Sideload", ignoreCase = true) ||
                                    it.threatType.contains("API", ignoreCase = true) ||
                                    it.threatType.contains("Permissions", ignoreCase = true)
                        }

                        val engineCCount = allThreats.count {
                            it.threatType.contains("Privacy", ignoreCase = true) ||
                                    it.threatType.contains("Sharing", ignoreCase = true) ||
                                    it.threatType.contains("Data", ignoreCase = true)
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
// Note: ThreatLogViewModelFactory is intentionally NOT here. It is imported from ThreatLogViewModel.kt!