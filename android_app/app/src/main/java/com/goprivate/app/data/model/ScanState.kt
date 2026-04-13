@file:Suppress("unused")

package com.goprivate.app.data.model

/**
 * Scan progress state for Scanner UI
 * Tracks scanning progress and results
 */
data class ScanState(
    val isScanning: Boolean = false,
    val progress: Int = 0,
    val totalApps: Int = 0,
    val scannedApps: Int = 0,
    val threatsFound: Int = 0
)