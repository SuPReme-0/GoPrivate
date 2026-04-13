@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.fragments

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.text.TextUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.data.model.VpnMode
import com.goprivate.app.databinding.FragmentSettingsBinding
import com.goprivate.app.core.network.GoPrivateVpnService
import com.goprivate.app.core.sensors.PrivacyAuditorService
import com.goprivate.app.ui.viewmodels.SettingsViewModel
import com.goprivate.app.ui.viewmodels.SettingsViewModelFactory
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import androidx.core.net.toUri

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    private val viewModel: SettingsViewModel by viewModels {
        SettingsViewModelFactory(requireActivity().application)
    }
    // 🚨 PERMISSION LAUNCHERS
    private val requestNotificationLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            // FIXED: Using 'notifications' and 'fileAccess' to match the ViewModel
            viewModel.updateOsPermissionState(notifications = true, fileAccess = binding.fileAccessSwitch.isChecked)
            showToast("Threat Alerts Enabled.")
        } else {
            binding.notificationsSwitch.isChecked = false
            showToast("Alerts Denied. Please enable in Android Settings.")
        }
    }

    private val requestStorageLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            // FIXED: Using 'notifications' and 'fileAccess' to match the ViewModel
            viewModel.updateOsPermissionState(notifications = binding.notificationsSwitch.isChecked, fileAccess = true)
            showToast("Engine B Payload Scanner Armed.")
        } else {
            binding.fileAccessSwitch.isChecked = false
            showToast("Storage Denied. File scan disabled.")
        }
    }
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupUI()
        observeViewModel()
    }

    override fun onResume() {
        super.onResume()
        // 🚨 HARD-SYNC: Every time the user opens this screen, force the switches to match actual OS reality
        syncSwitchesWithSystemReality()
    }

    private fun setupUI() {

        // ------------------------------------------------------------------
        // [ ENGINE MANAGEMENT ]
        // ------------------------------------------------------------------

        // Engine B: Static File Scanner
        binding.fileAccessSwitch.setOnClickListener {
            if (binding.fileAccessSwitch.isChecked) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    try {
                        val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                        intent.data = "package:${requireContext().packageName}".toUri()
                        startActivity(intent)
                    } catch (e: Exception) {
                        startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    }
                } else {
                    requestStorageLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                }
            } else {
                openAppSettings("Disable Storage Access in Android Settings to disarm Engine B.")
                binding.fileAccessSwitch.isChecked = true // Bounce back until OS confirms denial
            }
        }

        // Engine C: Autonomous Privacy Auditor
        binding.auditorSwitch.setOnClickListener {
            if (binding.auditorSwitch.isChecked) {
                showToast("Select 'GoPrivate' in Accessibility to arm Engine C.")
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            } else {
                showToast("Disable 'GoPrivate' in Accessibility to disarm Engine C.")
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                binding.auditorSwitch.isChecked = true // Bounce back until OS confirms denial
            }
        }

        // ------------------------------------------------------------------
        // [ NETWORK FIREWALL ]
        // ------------------------------------------------------------------

        // Autonomous VPN Ignition
        binding.vpnModeSwitch.setOnClickListener {
            val isChecked = binding.vpnModeSwitch.isChecked

            if (!isChecked) {
                // 🛑 USER TRIGGERED MANUAL MODE: Safe to save and kill tunnel
                viewModel.setVpnMode(VpnMode.MANUAL)

                val killIntent = Intent(requireContext(), GoPrivateVpnService::class.java).apply {
                    action = "ACTION_DISCONNECT_VPN"
                }
                requireContext().startService(killIntent)
                showToast("VPN Terminated. Switched to Manual Mode.")

            } else {
                // 🟢 USER TRIGGERED AUTO MODE: Attempt Ignition
                val vpnPermissionIntent = android.net.VpnService.prepare(requireContext())

                if (vpnPermissionIntent != null) {
                    // 🚨 PERMISSION DENIED: Do NOT save to ViewModel. Just revert UI.
                    showToast("OS Permission Required. Ignite VPN from the Dashboard radar first.")
                    binding.vpnModeSwitch.isChecked = false
                } else {
                    // ✅ PERMISSION GRANTED: Safe to save to database and start VPN!
                    viewModel.setVpnMode(VpnMode.AUTO)

                    val startIntent = Intent(requireContext(), GoPrivateVpnService::class.java).apply {
                        action = "ACTION_START_VPN"
                    }
                    ContextCompat.startForegroundService(requireContext(), startIntent)
                    showToast("Autonomous Ignition Armed.")
                }
            }
        }

        // Real-Time Threat Alerts
        binding.notificationsSwitch.setOnClickListener {
            if (binding.notificationsSwitch.isChecked) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    requestNotificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    showToast("Threat Alerts Enabled.")
                }
            } else {
                openAppSettings("Disable Notifications in Android Settings.")
                binding.notificationsSwitch.isChecked = true // Bounce back
            }
        }

        // ------------------------------------------------------------------
        // [ TELEMETRY & DANGER ZONE ]
        // ------------------------------------------------------------------

        binding.telemetrySwitch.setOnCheckedChangeListener { _, isChecked ->
            viewModel.toggleTelemetry(isChecked)
            TelemetryManager.isTelemetryEnabled = isChecked
        }

        binding.clearHistoryButton.setOnClickListener {
            viewModel.clearThreatHistory()
            showToast("🚨 Threat Database Purged Successfully.")
        }
    }

    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.settingsState.collectLatest { state ->
                binding.telemetrySwitch.isChecked = state.telemetryEnabled
                binding.vpnModeSwitch.isChecked = state.vpnMode == VpnMode.AUTO
            }
        }
    }

    /**
     * 🚨 THE TRUTH SERUM
     * Verifies actual OS-level permissions and forces the UI switches to match.
     */
    private fun syncSwitchesWithSystemReality() {
        // 1. Check Notifications
        val notifsGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        } else true
        binding.notificationsSwitch.isChecked = notifsGranted

        // 2. Check File Storage
        val storageGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        }
        binding.fileAccessSwitch.isChecked = storageGranted

        // 3. Check Accessibility
        binding.auditorSwitch.isChecked = isAccessibilityServiceEnabled()

        // 🚨 FIXED: Sync to backend using correct parameter names
        viewModel.updateOsPermissionState(notifications = notifsGranted, fileAccess = storageGranted)
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val expectedComponentName = ComponentName(requireContext(), PrivacyAuditorService::class.java)
        val enabledServicesSetting = Settings.Secure.getString(
            requireContext().contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false

        val colonSplitter = TextUtils.SimpleStringSplitter(':')
        colonSplitter.setString(enabledServicesSetting)
        while (colonSplitter.hasNext()) {
            val componentNameString = colonSplitter.next()
            val enabledComponent = ComponentName.unflattenFromString(componentNameString)
            if (enabledComponent != null && enabledComponent == expectedComponentName) {
                return true
            }
        }
        return false
    }

    private fun openAppSettings(rationale: String) {
        showToast(rationale)
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = "package:${requireContext().packageName}".toUri()
        }
        startActivity(intent)
    }

    private fun showToast(message: String) {
        Toast.makeText(requireContext(), message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}