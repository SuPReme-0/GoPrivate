@file:Suppress("unused", "SpellCheckingInspection", "DEPRECATION", "DrawAllocation")

package com.goprivate.app.ui.views

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import com.goprivate.app.R
import kotlin.math.*
import kotlin.random.Random
import androidx.core.graphics.withRotation

/**
 * Tactical Terminal Radar.
 * Sharp, hardware-accelerated geometry. Zero glow, pure data visualization.
 */
class CyberRadarView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    // === PRE-ALLOCATED PAINTS (Terminal Aesthetic) ===

    // Sharp terminal green for the main grid
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 1f // Ultra-fine lines
        color = ContextCompat.getColor(context, R.color.terminal_text_dim)
    }

    // Brighter green for the sweeping line
    private val scanLinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = ContextCompat.getColor(context, R.color.neon_green_primary)
    }

    // Solid sweep gradient (No blur, sharp edges)
    private val sweepPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }

    // Threat markers (Sharp Red)
    private val threatPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.alert_red_primary)
        style = Paint.Style.FILL
    }

    // Normal traffic markers (Dim Green)
    private val trafficPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.neon_green_primary)
        style = Paint.Style.FILL
    }

    // === OBJECT POOLS (Zero allocation during animation) ===
    private val trafficPool = Array(30) { NetworkNode() }
    private val threatPool = Array(10) { NetworkNode() }

    // === ANIMATION ===
    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 4000 // Slow, deliberate tactical sweep
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
    }

    // === STATE ===
    private var centerX = 0f
    private var centerY = 0f
    private var radius = 0f
    private var scanAngle = 0f

    init {
        setLayerType(LAYER_TYPE_HARDWARE, null)

        animator.addUpdateListener {
            updateNodes()
            scanAngle = (scanAngle + 1.5f) % 360f // Smooth rotation
            invalidate()
        }
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

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        centerX = w / 2f
        centerY = h / 2f
        radius = min(w, h) / 2f - 10f // Maximize screen space

        val greenRaw = ContextCompat.getColor(context, R.color.neon_green_primary)

        // Sharp gradient tail
        sweepPaint.shader = SweepGradient(
            centerX, centerY,
            intArrayOf(Color.TRANSPARENT, Color.TRANSPARENT, adjustAlpha(greenRaw, 0.4f), greenRaw),
            floatArrayOf(0f, 0.7f, 0.98f, 1f)
        )
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        drawTacticalGrid(canvas)
        drawNodes(canvas)
        drawScanner(canvas)
    }

    private fun drawTacticalGrid(canvas: Canvas) {
        // Concentric Rings
        for (i in 1..4) {
            canvas.drawCircle(centerX, centerY, radius * (i / 4f), gridPaint)
        }

        // Crosshairs
        canvas.drawLine(centerX - radius, centerY, centerX + radius, centerY, gridPaint)
        canvas.drawLine(centerX, centerY - radius, centerX, centerY + radius, gridPaint)

        // 45 Degree diagonals
        canvas.drawLine(centerX - radius * 0.7f, centerY - radius * 0.7f, centerX + radius * 0.7f, centerY + radius * 0.7f, gridPaint)
        canvas.drawLine(centerX - radius * 0.7f, centerY + radius * 0.7f, centerX + radius * 0.7f, centerY - radius * 0.7f, gridPaint)
    }

    private fun drawScanner(canvas: Canvas) {
        canvas.withRotation(scanAngle, centerX, centerY) {
            // Draw the sweeping wedge
            drawCircle(centerX, centerY, radius, sweepPaint)

            // Draw the leading hard edge line
            drawLine(centerX, centerY, centerX + radius, centerY, scanLinePaint)

        }
    }

    private fun drawNodes(canvas: Canvas) {
        for (node in trafficPool) {
            if (node.isActive) {
                trafficPaint.alpha = (255 * node.alpha).toInt()
                canvas.drawRect(
                    node.x - 2f, node.y - 2f,
                    node.x + 2f, node.y + 2f,
                    trafficPaint
                ) // Draw as tiny squares (data packets)
            }
        }
        for (node in threatPool) {
            if (node.isActive) {
                canvas.drawCircle(node.x, node.y, 6f, threatPaint) // Draw threats as larger red circles

                // Draw tactical box around threat
                canvas.drawRect(
                    node.x - 10f, node.y - 10f,
                    node.x + 10f, node.y + 10f,
                    gridPaint
                )
            }
        }
    }

    private fun updateNodes() {
        // Randomly spawn normal traffic
        if (Random.nextFloat() > 0.92f && trafficPool.count { it.isActive } < 30) {
            spawnNode(trafficPool, isThreat = false)
        }

        for (node in trafficPool) {
            if (node.isActive) node.update(centerX, centerY, radius)
        }
        for (node in threatPool) {
            if (node.isActive) node.update(centerX, centerY, radius)
        }
    }

    /**
     * Public function to be called by HomeViewModel when Engine A or B flags malware.
     */
    fun addThreatMarker() {
        spawnNode(threatPool, isThreat = true)
        invalidate()
    }

    private fun spawnNode(pool: Array<NetworkNode>, isThreat: Boolean) {
        for (node in pool) {
            if (!node.isActive) {
                node.reset(centerX, centerY, isThreat)
                return
            }
        }
    }

    private fun adjustAlpha(color: Int, factor: Float): Int {
        val alpha = (Color.alpha(color) * factor).roundToInt()
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
    }

    /**
     * Internal data class representing a packet on the radar.
     */
    private class NetworkNode {
        var isActive = false
        private var isThreat = false
        private var angleRad = 0f
        private var speed = 0f
        private var distanceRatio = 0f
        var alpha = 1f
        var x = 0f
        var y = 0f

        fun reset(cX: Float, cY: Float, threat: Boolean) {
            isActive = true
            isThreat = threat
            angleRad = (Random.nextFloat() * 360f) * (Math.PI / 180).toFloat()
            // Threats move slower so the user can see them
            speed = if (threat) 0.005f else 0.015f
            distanceRatio = 1.0f // Start at outer edge
            alpha = 1f
            x = cX
            y = cY
        }

        fun update(cX: Float, cY: Float, maxR: Float) {
            distanceRatio -= speed

            if (distanceRatio <= 0) {
                isActive = false
                return
            }

            // Fade out normal traffic as it gets closer to center
            if (!isThreat) {
                alpha = distanceRatio.coerceIn(0.1f, 1f)
            }

            val actualDist = distanceRatio * maxR
            x = cX + cos(angleRad) * actualDist
            y = cY + sin(angleRad) * actualDist
        }
    }
}