@file:Suppress("unused")

package com.goprivate.app.data.model

/**
 * Detection sensitivity levels for ML engines
 */
enum class DetectionThreshold(val value: Float, val displayName: String) {
    LENIENT(0.75f, "Lenient"),
    BALANCED(0.50f, "Balanced"),
    PARANOID(0.25f, "Paranoid")
}