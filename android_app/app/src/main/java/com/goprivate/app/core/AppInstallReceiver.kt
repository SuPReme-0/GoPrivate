package com.goprivate.app.core

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.goprivate.app.core.services.AppScannerService

/**
 * 🚨 THE SIDELOAD INTERCEPTOR
 * Listens for new app installations. Operates as a Microsecond Relay.
 * Hands heavy ML inference off to the immortal AppScannerService to comply
 * with strict Android 14 Background Execution Limits.
 */
class AppInstallReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "AppInstallReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action

        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            // Android passes the package name in the intent data URI (e.g., package:com.example.malware)
            val packageName = intent.data?.schemeSpecificPart ?: return

            // 🚨 OROBOUROS AVOIDANCE: Never scan ourselves
            if (packageName == context.packageName) return

            Log.d(TAG, "📦 New module detected: $packageName. Handing off to Vanguard Scanner...")

            TelemetryManager.logToTerminal("SYS", "Sideload Interceptor: New package [$packageName] detected.")

            // 🚨 THE HANDOFF PROTOCOL
            // We do not run Engine B here. We wake up the Foreground Service to do it.
            // The Foreground Service has unlimited time and CPU priority to run the massive ONNX matrix.
            try {
                val scanIntent = Intent(context, AppScannerService::class.java).apply {
                    this.action = AppScannerService.ACTION_START_SINGLE_SCAN
                    putExtra(AppScannerService.EXTRA_PACKAGE_NAME, packageName)
                }

                // If Android 8+, we must use startForegroundService to wake a service from the background
                context.startForegroundService(scanIntent)

                Log.d(TAG, "✅ Handoff complete. Receiver going back to sleep.")
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to relay package to Vanguard Scanner", e)
            }
        }
    }
}