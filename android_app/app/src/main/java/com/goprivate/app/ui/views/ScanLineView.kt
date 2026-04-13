@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.views

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import com.goprivate.app.R

/**
 * Animated scan line overlay for terminal vibe.
 * Zero allocations during draw. Hardware accelerated.
 */
class ScanLineView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    // Pre-allocated scan paint (zero allocation in onDraw)
    private val scanPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.scan_line)
        strokeWidth = 2f
    }

    private var yOffset = 0f

    // Animation
    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 3000
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener {
            yOffset = (it.animatedValue as Float) * height
            invalidate()
        }
    }

    init {
        setLayerType(LAYER_TYPE_HARDWARE, null)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        animator.start()
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        animator.cancel()
        setLayerType(LAYER_TYPE_NONE, null)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawLine(0f, yOffset, width.toFloat(), yOffset, scanPaint)
    }
}