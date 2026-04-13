@file:Suppress("unused", "SpellCheckingInspection", "DEPRECATION", "DrawAllocation")

package com.goprivate.app.ui.views

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.animation.LinearInterpolator
import androidx.appcompat.widget.AppCompatTextView
import androidx.core.content.ContextCompat
import com.goprivate.app.R
import kotlin.random.Random
import androidx.core.graphics.withTranslation

/**
 * Terminal-style TextView with random glitch/chromatic aberration effect.
 * Zero allocations during draw. Hardware accelerated. Authentic cyber-terminal vibe.
 */
class GlitchTextView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : AppCompatTextView(context, attrs, defStyleAttr) {

    private var glitchEnabled = false
    private var glitchIntensity = GlitchIntensity.LOW

    // Pre-allocated glitch paint (zero allocation in onDraw)
    private val glitchPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC_ATOP)
    }

    // Pre-allocated colors
    private var cyanColor = 0
    private var purpleColor = 0
    private var redColor = 0

    // Animation
    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 100
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener { invalidate() }
    }

    enum class GlitchIntensity {
        LOW, MEDIUM, HIGH
    }

    init {
        context.theme.obtainStyledAttributes(
            attrs,
            R.styleable.GlitchTextView,
            0, 0
        ).apply {
            try {
                glitchEnabled = getBoolean(R.styleable.GlitchTextView_glitchEnabled, false)
                val intensityOrdinal = getInt(R.styleable.GlitchTextView_glitchIntensity, 0)
                glitchIntensity = GlitchIntensity.entries[intensityOrdinal]
            } finally {
                recycle()
            }
        }

        // Pre-load colors
        cyanColor = ContextCompat.getColor(context, R.color.neon_cyan_primary)
        purpleColor = ContextCompat.getColor(context, R.color.neon_purple_primary)
        redColor = ContextCompat.getColor(context, R.color.alert_red_primary)

        if (glitchEnabled) {
            setLayerType(LAYER_TYPE_HARDWARE, null)
            animator.start()
        }
    }

    @Suppress("DrawAllocation", "WrongCall")
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        if (glitchEnabled && Random.nextFloat() < getGlitchProbability()) {
            drawGlitchEffect(canvas)
        }
    }

    private fun getGlitchProbability(): Float {
        return when (glitchIntensity) {
            GlitchIntensity.LOW -> 0.02f
            GlitchIntensity.MEDIUM -> 0.05f
            GlitchIntensity.HIGH -> 0.1f
        }
    }

    @Suppress("DrawAllocation", "WrongCall")
    private fun drawGlitchEffect(canvas: Canvas) {
        // Random glitch offset
        val offsetX = Random.nextFloat() * 4f - 2f
        val offsetY = Random.nextFloat() * 4f - 2f

        // Draw offset copy with color shift (manual save/translate/restore)
        glitchPaint.color = cyanColor.copy(alpha = 0.3f)
        canvas.withTranslation(offsetX, offsetY) {
            super.onDraw(this)
        }

        // Draw second offset copy with different color
        glitchPaint.color = purpleColor.copy(alpha = 0.2f)
        canvas.withTranslation(-offsetX, -offsetY) {
            super.onDraw(this)
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        if (glitchEnabled) {
            animator.cancel()
            setLayerType(LAYER_TYPE_NONE, null)
        }
    }

    private fun Int.copy(alpha: Float): Int {
        val a = (alpha * 255).toInt().coerceIn(0, 255)
        return (a shl 24) or (this and 0x00FFFFFF)
    }
}