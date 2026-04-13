package com.goprivate.app.core.sensors

import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

/**
 * 🕸️ Advanced Headless Web Scraper (Project Trinity)
 * Spins up an invisible Chromium engine to render React/Angular JS payloads,
 * extracts the rendered human text, and cleanly chunks it for DistilBERT (Engine C).
 */
object WebScraperUtility {
    private const val TAG = "WebScraper"

    @SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
    suspend fun scrapeAndCleanHtml(context: Context, urlStr: String): List<String> = suspendCancellableCoroutine { continuation ->

        // 🚨 RACE CONDITION FIX: Thread-safe lock guarantees the coroutine is only resumed EXACTLY once.
        val isResumed = AtomicBoolean(false)
        val safeContext = context.applicationContext // 🚨 MEMORY LEAK FIX: Force Application Context

        Handler(Looper.getMainLooper()).post {
            try {
                val webView = WebView(safeContext)

                // ANTI-MEMORY-LEAK: If the caller (PrivacyAuditor) times out after 15s, nuke the WebView
                continuation.invokeOnCancellation {
                    if (isResumed.compareAndSet(false, true)) {
                        Handler(Looper.getMainLooper()).post {
                            try { webView.destroy() } catch (_: Exception) {}
                        }
                    }
                }

                webView.settings.apply {
                    javaScriptEnabled = true
                    domStorageEnabled = true
                    blockNetworkImage = true // Saves bandwidth and speeds up rendering
                    mediaPlaybackRequiresUserGesture = true
                }

                webView.addJavascriptInterface(object : Any() {
                    @JavascriptInterface
                    fun processRenderedText(renderedText: String) {
                        if (isResumed.compareAndSet(false, true)) {
                            kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
                                val sentences = chunkText(renderedText)
                                Log.d(TAG, "🌐 Extracted ${sentences.size} dynamic NLP chunks from $urlStr")

                                continuation.resume(sentences)

                                // Clean up RAM on the main thread after success
                                Handler(Looper.getMainLooper()).post {
                                    try { webView.destroy() } catch (_: Exception) {}
                                }
                            }
                        }
                    }
                }, "KotlinBridge")

                webView.webViewClient = object : WebViewClient() {

                    // 🚨 IFRAME SPAM FIX: Only trigger the JS extraction on the main page frame
                    override fun onPageFinished(view: WebView?, url: String?) {
                        if (url == urlStr && !isResumed.get()) {
                            // Give React/Angular 1.5 seconds to hydrate the DOM
                            Handler(Looper.getMainLooper()).postDelayed({
                                if (!isResumed.get()) {
                                    view?.loadUrl("javascript:window.KotlinBridge.processRenderedText(document.body.innerText);")
                                }
                            }, 1500)
                        }
                    }

                    override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) {
                        // Only abort if the MAIN frame fails to load. Ignore background ad-tracker failures.
                        if (request?.isForMainFrame == true) {
                            Log.e(TAG, "❌ Headless Browser Error on $urlStr: ${error?.description}")

                            if (isResumed.compareAndSet(false, true)) {
                                continuation.resume(emptyList())
                                Handler(Looper.getMainLooper()).post {
                                    try { view?.destroy() } catch (_: Exception) {}
                                }
                            }
                        }
                    }
                }

                Log.d(TAG, "🕸️ Booting headless Chromium for JS Hydration: $urlStr...")
                webView.loadUrl(urlStr)

            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to boot Headless Scraper", e)
                if (isResumed.compareAndSet(false, true)) {
                    continuation.resume(emptyList())
                }
            }
        }
    }

    /**
     * Cleans the text for DistilBERT without destroying necessary grammatical context.
     */
    private fun chunkText(rawText: String): List<String> {
        // 🚨 NLP SABOTAGE FIX: We keep hyphens, colons, quotes, and standard punctuation.
        // We only strip out bizarre unicode symbols and normalize whitespace.
        val cleanText = rawText
            .replace(Regex("\\s+"), " ") // Normalize tabs/newlines/multiple spaces into a single space
            .replace(Regex("[^\\p{L}\\p{N}\\p{P}\\s]"), "") // Keep Letters, Numbers, Punctuation, and Spaces

        // Split by sentences (lookbehind for periods/exclamation/questions followed by a space)
        return cleanText.split(Regex("(?<=[.!?])\\s+"))
            .map { it.trim() }
            .filter { it.length > 40 } // Ignore short UI artifacts like "Sign In" or "Accept Cookies"
    }
}