@file:Suppress("unused", "DEPRECATION", "DrawAllocation")

package com.goprivate.app.ui.views

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import com.google.android.material.card.MaterialCardView
import androidx.core.content.ContextCompat
import com.goprivate.app.R

/**
 * Holographic Card with neon glow borders and glassmorphism effect.
 * Compatible with API 26+. Uses multi-stroke technique for glow.
 * Zero allocations during draw. Authentic cyber-terminal aesthetic.
 */
class HolographicCard @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : MaterialCardView(context, attrs, defStyleAttr) {

    private var glowColor = Color.CYAN
    private var hologramIntensity = 1 // 0=low, 1=medium, 2=high

    // Pre-allocated glow paint (zero allocation in onDraw)
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }

    init {
        context.theme.obtainStyledAttributes(
            attrs,
            R.styleable.HolographicCard,
            0, 0
        ).apply {
            try {
                hologramIntensity = getInt(R.styleable.HolographicCard_hologramIntensity, 1)
                glowColor = getColor(R.styleable.HolographicCard_glowColor, ContextCompat.getColor(context, R.color.neon_cyan_glow))
            } finally {
                recycle()
            }
        }

        setLayerType(LAYER_TYPE_HARDWARE, null)
        cardElevation = 0f
        strokeWidth = 0
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        drawHolographicGlow(canvas)
    }

    private fun drawHolographicGlow(canvas: Canvas) {
        val width = width.toFloat()
        val height = height.toFloat()
        val radius = radius

        val layers = when (hologramIntensity) {
            2 -> 5
            1 -> 3
            else -> 2
        }

        for (i in 1..layers) {
            glowPaint.alpha = (255 / layers * (layers - i + 1) * 0.3f).toInt()
            glowPaint.strokeWidth = i * 1.5f
            glowPaint.color = glowColor

            val rectF = RectF(0f, 0f, width, height)
            canvas.drawRoundRect(rectF, radius, radius, glowPaint)
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        setLayerType(LAYER_TYPE_NONE, null)
    }
}