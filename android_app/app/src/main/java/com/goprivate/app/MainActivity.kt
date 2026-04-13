@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app

import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.view.GravityCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.core.network.GoPrivateVpnService
import com.goprivate.app.core.sensors.PrivacyAuditorService
import com.goprivate.app.data.ml.EngineANetworkManager
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.ml.EngineCNLPManager
import com.goprivate.app.databinding.ActivityMainBinding
import com.goprivate.app.ui.fragments.HomeFragment
import com.goprivate.app.ui.fragments.ScannerFragment
import com.goprivate.app.ui.fragments.SettingsFragment
import com.goprivate.app.ui.fragments.ThreatLogFragment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Main Activity - Cyber Terminal Entry Point
 * Industry-grade architecture integrating DrawerLayout, BottomNav, and Parallel ML Booting.
 */
class MainActivity : AppCompatActivity() {

    private companion object {
        private const val TAG = "MainActivity"
    }

    private lateinit var binding: ActivityMainBinding

    // 🛡️ Modern VPN Permission Launcher
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "VPN permission denied. Shield deactivated.", Toast.LENGTH_LONG).show()
            Log.w(TAG, "User denied VPN permission")
        }
    }

    // 🔔 Modern Notification Permission Launcher (Android 13+)
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (!isGranted) {
            Log.w(TAG, "Notification permission denied. Threat alerts will be silent.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🚨 WAKE UP THE REPOSITORY!
        com.goprivate.app.data.repository.ThreatRepository.initialize(applicationContext)

        // Force Dark Theme for Terminal Aesthetic
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)

        // Initialize ViewBinding
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // === SYSTEM WIRING ===
        setupToolbarAndDrawer()
        setupBottomNavigation()
        initializeEngines() // 🚨 Triggers the Parallel Bootloader

        // 🚨 CHECK DAEMON STATUS
        checkAndAnnounceAuditorStatus()

        // Load default fragment
        if (savedInstanceState == null) {
            loadFragment(HomeFragment())
            binding.bottomNavigation.selectedItemId = R.id.nav_home
        }

        // Request Notification Permission on boot for Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val permissionStatus = ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
            if (permissionStatus != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun setupToolbarAndDrawer() {
        binding.topToolbar.setNavigationOnClickListener {
            binding.drawerLayout.openDrawer(GravityCompat.START)
        }

        binding.navView.setNavigationItemSelectedListener { menuItem ->
            when (menuItem.itemId) {
                R.id.side_nav_dashboard -> binding.bottomNavigation.selectedItemId = R.id.nav_home
                R.id.side_nav_app_auditor -> binding.bottomNavigation.selectedItemId = R.id.nav_scanner
                R.id.side_nav_settings -> binding.bottomNavigation.selectedItemId = R.id.nav_settings
                R.id.side_nav_firewall -> loadFragment(ThreatLogFragment())
                R.id.side_nav_kill_switch -> {
                    stopService(Intent(this, GoPrivateVpnService::class.java))
                    Toast.makeText(this, "Network Kill Switch Activated", Toast.LENGTH_SHORT).show()
                }
            }
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            true
        }

        binding.shieldIndicator.setOnClickListener {
            binding.bottomNavigation.selectedItemId = R.id.nav_settings
        }
    }

    private fun setupBottomNavigation() {
        binding.bottomNavigation.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> {
                    loadFragment(HomeFragment())
                    binding.topToolbar.title = ">_ GoPrivate_Core"
                    true
                }
                R.id.nav_scanner -> {
                    loadFragment(ScannerFragment())
                    binding.topToolbar.title = ">_ System_Audit"
                    true
                }
                R.id.nav_settings -> {
                    loadFragment(SettingsFragment())
                    binding.topToolbar.title = ">_ Sys_Config"
                    true
                }
                else -> false
            }
        }
    }

    private fun loadFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .setCustomAnimations(android.R.anim.fade_in, android.R.anim.fade_out)
            .replace(R.id.fragment_container, fragment)
            .commit()
    }

    /**
     * 🚨 Parallel ML Bootloader.
     * Spreads ONNX decryption across multiple CPU cores, preventing Main Thread starvation.
     */
    private fun initializeEngines() {
        lifecycleScope.launch(Dispatchers.Default) {
            try {
                Log.d(TAG, "🚀 Commencing Parallel ML Engine Boot Sequence...")

                val engineA = async { EngineANetworkManager.initialize(applicationContext) }
                val engineB = async { EngineBStaticManager.initialize(applicationContext) }
                val engineC = async { EngineCNLPManager.initialize(applicationContext) }

                awaitAll(engineA, engineB, engineC)

                withContext(Dispatchers.Main) {
                    Log.d(TAG, "✅ All ML Engines Online and Synchronized.")
                    TelemetryManager.logToTerminal("SYS", "All Matrix Engines Online.")
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Critical Failure during ML Boot Sequence", e)
                withContext(Dispatchers.Main) {
                    TelemetryManager.logToTerminal("ERR", "SYSTEM BOOT FAILURE. Engine offline.")
                }
            }
        }

        // UI OBSERVER: Isolated from the bootloader
        lifecycleScope.launch {
            EngineANetworkManager.vpnActiveFlow.collect { active ->
                updateShieldStatus(active)
            }
        }
    }

    /**
     * Updates the Top-Right Logo.
     * 🚨 KOTLIN FIX: Using Alpha transparency instead of ColorFilter so the logo's true colors survive.
     */
    fun updateShieldStatus(active: Boolean) {
        if (active) {
            binding.shieldIndicator.clearColorFilter()
            binding.shieldIndicator.alpha = 1.0f
            binding.shieldIndicator.contentDescription = getString(R.string.msg_vpn_active)
        } else {
            binding.shieldIndicator.clearColorFilter()
            binding.shieldIndicator.alpha = 0.4f
            binding.shieldIndicator.contentDescription = getString(R.string.msg_vpn_inactive)
        }
    }

    // =========================================================================================
    // 🚨 PUBLIC API FOR FRAGMENTS (DAEMON & VPN CONTROLS)
    // =========================================================================================

    fun requestVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, GoPrivateVpnService::class.java)
        ContextCompat.startForegroundService(this, intent)
        Toast.makeText(this, "ML Shield Activated", Toast.LENGTH_SHORT).show()
    }

    /**
     * 🚨 DAEMON API: Warps the user to the Android OS settings to grant Immortality to Engine C.
     */
    fun requestAccessibility() {
        Toast.makeText(this, "Please enable the GoPrivate Privacy Auditor", Toast.LENGTH_LONG).show()
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        startActivity(intent)
    }

    /**
     * 🚨 DAEMON API: Safely checks the Android Secure Settings to see if the Auditor is immortalized.
     */
    fun isAccessibilityEnabled(): Boolean {
        var accessibilityEnabled = 0
        val service = packageName + "/" + PrivacyAuditorService::class.java.canonicalName
        try {
            accessibilityEnabled = Settings.Secure.getInt(
                contentResolver,
                Settings.Secure.ACCESSIBILITY_ENABLED
            )
        } catch (e: Settings.SettingNotFoundException) {
            Log.e(TAG, "Accessibility setting not found: ${e.message}")
        }

        val stringColonSplitter = TextUtils.SimpleStringSplitter(':')
        if (accessibilityEnabled == 1) {
            val settingValue = Settings.Secure.getString(
                contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            if (settingValue != null) {
                stringColonSplitter.setString(settingValue)
                while (stringColonSplitter.hasNext()) {
                    val accessibilityService = stringColonSplitter.next()
                    if (accessibilityService.equals(service, ignoreCase = true)) {
                        return true
                    }
                }
            }
        }
        return false
    }

    /**
     * 🚨 DAEMON API: Syncs the status of the immortal engine to the Home Terminal
     */
    private fun checkAndAnnounceAuditorStatus() {
        lifecycleScope.launch(Dispatchers.IO) {
            // Slight delay so it appears chronologically after the boot sequence logs
            delay(1000)
            if (isAccessibilityEnabled()) {
                TelemetryManager.logToTerminal("SYS", "KERNEL DAEMON ACTIVE: Privacy Auditor is Immortal.")
            } else {
                TelemetryManager.logToTerminal("WRN", "DAEMON OFFLINE: Privacy Auditor requires Accessibility Permission.")
            }
        }
    }

    @SuppressLint("GestureBackNavigation")
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (binding.drawerLayout.isDrawerOpen(GravityCompat.START)) {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
        } else {
            super.onBackPressed()
        }
    }
}