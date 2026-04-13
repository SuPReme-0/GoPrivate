@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.goprivate.app.MainActivity
import com.goprivate.app.R
import com.goprivate.app.databinding.ActivitySplashBinding


/**
 * Splash Activity - Cyber Terminal Entry Point
 * Uses Android 12+ SplashScreen API with fallback for older versions.
 * Shows logo with Enter button, then redirects to MainActivity.
 */
@SuppressLint("CustomSplashScreen")
class SplashActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySplashBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        // Install SplashScreen (Android 12+ API) - must be called before super.onCreate()
        installSplashScreen()

        super.onCreate(savedInstanceState)

        // Apply splash theme (no action bar, full screen)
        setTheme(R.style.Theme_GoPrivate_Splash)

        // Initialize ViewBinding
        binding = ActivitySplashBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Setup UI
        setupUI()
    }

    private fun setupUI() {
        // Enter button click: Navigate to MainActivity
        binding.enterButton.setOnClickListener {
            navigateToMain()
        }

        // Also allow tap anywhere on logo to continue
        binding.appLogo.setOnClickListener {
            navigateToMain()
        }
    }

    private fun navigateToMain() {
        // Disable button to prevent double-tap
        binding.enterButton.isEnabled = false

        // Navigate to MainActivity with fade transition
        // Using ActivityOptions for modern transition (API 21+)
        val options = android.app.ActivityOptions.makeCustomAnimation(
            this,
            android.R.anim.fade_in,
            android.R.anim.fade_out
        )
        startActivity(Intent(this, MainActivity::class.java), options.toBundle())
        finish()
    }

    // ✅ FIXED: Removed onBackPressed override (not needed for splash screen)
    // If you must override, use this pattern:
    /*
    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        // Prevent back navigation from splash screen
        // User must press Enter to proceed
        // super.onBackPressed() // Optional: call if you want default behavior
    }
    */
}