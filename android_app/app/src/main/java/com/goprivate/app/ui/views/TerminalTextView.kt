@file:Suppress("unused", "DEPRECATION")

package com.goprivate.app.ui.views

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import androidx.appcompat.widget.AppCompatTextView
import androidx.core.content.ContextCompat
import com.goprivate.app.R
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collectLatest

/**
 * Terminal-style TextView with typewriter effect and blinking cursor.
 * Zero allocations during draw. Coroutine-based animation with proper cancellation.
 */
class TerminalTextView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : AppCompatTextView(context, attrs, defStyleAttr) {

    private var typewriterEnabled = false

    private val cursorPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.terminal_cursor)
        style = Paint.Style.FILL
    }

    // Text state
    private val _fullText = MutableStateFlow("")
    private var displayedText = ""
    private var cursorVisible = true

    // Coroutine scopes
    private val mainScope = CoroutineScope(Dispatchers.Main.immediate + SupervisorJob())
    private var typewriterJob: Job? = null
    private var cursorJob: Job? = null

    init {
        context.theme.obtainStyledAttributes(
            attrs,
            R.styleable.TerminalTextView,
            0, 0
        ).apply {
            try {
                typewriterEnabled = getBoolean(R.styleable.TerminalTextView_typewriterEnabled, false)
            } finally {
                recycle()
            }
        }

        if (typewriterEnabled) {
            startCursorBlink()
            observeTextChanges()
        }
    }

    /**
     * Observes the _fullText flow and starts the typewriter animation
     * whenever the text changes (even during an ongoing animation).
     */
    private fun observeTextChanges() {
        mainScope.launch {
            _fullText.collectLatest { newFullText ->
                // Cancel current typewriter animation if running
                typewriterJob?.cancel()
                // Reset displayed text
                displayedText = ""
                super.setText("", BufferType.NORMAL)
                // Start new animation
                typewriterJob = startTypewriter(newFullText)
            }
        }
    }

    override fun setText(text: CharSequence?, type: BufferType?) {
        if (typewriterEnabled && text != null) {
            // Update the flow – this will trigger observeTextChanges() automatically
            _fullText.value = text.toString()
        } else {
            super.setText(text, type)
        }
    }

    private fun startTypewriter(targetText: String): Job {
        return mainScope.launch {
            val length = targetText.length
            for (i in 0 until length) {
                // Stop animation if the target text changed in the meantime
                if (_fullText.value != targetText) break
                displayedText = targetText.substring(0, i + 1)
                super.setText(displayedText, BufferType.NORMAL)
                delay(30) // typing speed
            }
            // Ensure final text is set exactly (in case of rounding)
            if (_fullText.value == targetText && displayedText != targetText) {
                super.setText(targetText, BufferType.NORMAL)
            }
        }
    }

    private fun startCursorBlink() {
        cursorJob?.cancel()
        cursorJob = mainScope.launch {
            while (isActive) {
                cursorVisible = !cursorVisible
                invalidate()
                delay(500)
            }
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (typewriterEnabled && cursorVisible) {
            val textWidth = paint.measureText(displayedText)
            val cursorX = paddingStart + textWidth
            val cursorY = paddingTop + (height - paddingBottom - paddingTop) / 2f + paint.textSize / 3f
            canvas.drawRect(cursorX, cursorY - paint.textSize * 0.9f, cursorX + 2f, cursorY, cursorPaint)
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        typewriterJob?.cancel()
        cursorJob?.cancel()
        mainScope.cancel()
    }
}