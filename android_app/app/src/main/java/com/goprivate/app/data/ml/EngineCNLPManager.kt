@file:Suppress("SpellCheckingInspection", "UNCHECKED_CAST", "unused")

package com.goprivate.app.data.ml

import android.content.Context
import android.util.Log
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import com.goprivate.app.core.AssetHelper
import com.goprivate.app.core.DistilBertTokenizer
import com.goprivate.app.core.SecurityCore
import com.goprivate.app.core.TelemetryManager
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.LongBuffer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.math.exp

/**
 * 🛡️ THE NLP SENTINEL (ENGINE C)
 * Production-grade ONNX Inference Engine for Privacy & Phishing Analysis.
 * Upgraded with Hardware Thread Isolation to prevent VPN CPU Starvation.
 */
object EngineCNLPManager {
    private const val TAG = "EngineC_NLP"
    private const val MODEL_FILENAME = "engine_c_model.enc"

    // 🚨 QUARANTINE: A dedicated hardware thread solely for NLP math.
    // Prevents fighting with the VPN on Dispatchers.Default.
    private val NlpDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    private var ortEnv: OrtEnvironment? = null
    private var ortSession: OrtSession? = null
    private var tokenizer: DistilBertTokenizer? = null
    private var labelMapping: Map<Int, String>? = null

    private val _isAnalyzing = MutableStateFlow(false)
    val isAnalyzing: StateFlow<Boolean> = _isAnalyzing.asStateFlow()

    private val _nlpEvents = MutableSharedFlow<String>(replay = 0, extraBufferCapacity = 10)
    val nlpEventsFlow: SharedFlow<String> = _nlpEvents.asSharedFlow()

    @Volatile
    private var isInitialized = false
    private val isBooting = AtomicBoolean(false)

    private var bootDeferred = CompletableDeferred<Boolean>()
    private val managerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val engineLock = ReentrantReadWriteLock()
    private val inferenceMutex = Mutex()

    fun initialize(context: Context) {
        if (isInitialized) return
        if (isBooting.getAndSet(true)) return

        if (bootDeferred.isCompleted || bootDeferred.isCancelled) {
            bootDeferred = CompletableDeferred()
        }

        managerScope.launch(NlpDispatcher) {
            engineLock.writeLock().lock()
            try {
                if (isInitialized) {
                    bootDeferred.complete(true)
                    return@launch
                }

                tokenizer = DistilBertTokenizer(context)
                labelMapping = AssetHelper.loadEngineCLabelMapping(context)
                ortEnv = OrtEnvironment.getEnvironment()

                Log.d(TAG, "🔒 Streaming decryption for massive NLP model: $MODEL_FILENAME")
                val tempFilePath = SecurityCore.decryptModelToTempFile(context, MODEL_FILENAME)
                    ?: throw IllegalStateException("Streaming decryption failed")

                // 🚨 CPU STARVATION FIX: Clamp ONNX to exactly 1 thread.
                // Single-threaded NLP is faster under heavy VPN load because it stops OS context switching.
                val sessionOptions = OrtSession.SessionOptions().apply {
                    setIntraOpNumThreads(1)
                    setInterOpNumThreads(1)
                    try {
                        addXnnpack(emptyMap())
                        Log.d(TAG, "✅ XNNPACK execution provider enabled")
                    } catch (_: Exception) {
                        Log.w(TAG, "⚠️ XNNPACK not available, falling back to CPU")
                    }
                }

                ortSession = ortEnv?.createSession(tempFilePath, sessionOptions)

                val tempFile = java.io.File(tempFilePath)
                if (tempFile.exists()) tempFile.delete()

                isInitialized = true
                bootDeferred.complete(true)
                Log.d(TAG, "✅ ONNX Engine C Initialized (Encrypted, RAM-Safe, Thread-Isolated)!")
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to initialize Engine C", e)
                bootDeferred.complete(false)
                shutdownInternal()
            } finally {
                isBooting.set(false)
                engineLock.writeLock().unlock()
            }
        }
    }

    private fun calculateActualRisk(label: String, confidencePct: Float): Float {
        val normalized = label.lowercase()
        val confidence = confidencePct / 100f

        return when {
            normalized.contains("data_sharing") ||
                    normalized.contains("data_collection") ||
                    normalized.contains("phishing") ||
                    normalized.contains("scam") ||
                    normalized.contains("malware") -> confidence

            normalized.contains("other_policy") ||
                    normalized.contains("security_retention") ||
                    normalized.contains("user_choice") ||
                    normalized.contains("safe") ||
                    normalized.contains("benign") -> 0.0f

            else -> 0.0f
        }
    }

    // 🚨 EXECUTION SHIFT: Forcing all math onto the isolated NlpDispatcher
    suspend fun analyzePolicyClause(text: String, isSilent: Boolean = false): Pair<String, Float> = withContext(NlpDispatcher) {
        if (!isInitialized) {
            if (isBooting.get()) {
                try {
                    val success = bootDeferred.await()
                    if (!success || !isInitialized) return@withContext Pair("Error", 0f)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    return@withContext Pair("Error", 0f)
                }
            } else {
                return@withContext Pair("Error", 0f)
            }
        }

        if (!isSilent) {
            _isAnalyzing.value = true
            _nlpEvents.tryEmit(">>> INITIATING_NLP_ANALYSIS...")
        }

        if (text.isBlank() || text.length < 10) return@withContext Pair("Unknown", 0f)

        val startTimeMs = System.currentTimeMillis()
        var predictedLabel = "Error"
        var confidence = 0f

        try {
            val currentTokenizer = tokenizer ?: return@withContext Pair("Error", 0f)
            val currentMapping = labelMapping ?: return@withContext Pair("Error", 0f)

            val (inputIds, attentionMask) = currentTokenizer.tokenize(text)
            val shape = longArrayOf(1, inputIds.size.toLong())

            withContext(NonCancellable) {
                inferenceMutex.withLock {
                    engineLock.readLock().lock()
                    try {
                        val session = ortSession ?: return@withContext
                        val env = ortEnv ?: return@withContext

                        OnnxTensor.createTensor(env, LongBuffer.wrap(inputIds), shape).use { inputIdsTensor ->
                            OnnxTensor.createTensor(env, LongBuffer.wrap(attentionMask), shape).use { attentionMaskTensor ->

                                val inputs = java.util.HashMap<String, OnnxTensor>(2, 1.0f).apply {
                                    put("input_ids", inputIdsTensor)
                                    put("attention_mask", attentionMaskTensor)
                                }

                                session.run(inputs).use { result ->
                                    val logitsArray = (result[0].value as Array<FloatArray>)[0]

                                    softmaxInPlace(logitsArray)

                                    var maxIndex = 0
                                    var maxProb = logitsArray[0]
                                    for (i in 1 until logitsArray.size) {
                                        if (logitsArray[i] > maxProb) {
                                            maxProb = logitsArray[i]
                                            maxIndex = i
                                        }
                                    }

                                    predictedLabel = currentMapping[maxIndex] ?: "Unknown"
                                    confidence = maxProb * 100f
                                }
                            }
                        }
                    } finally {
                        engineLock.readLock().unlock()
                    }
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            return@withContext Pair("Error", 0f)
        }

        val actualRiskScore = calculateActualRisk(predictedLabel, confidence)
        val inferenceTimeMs = System.currentTimeMillis() - startTimeMs

        TelemetryManager.logInference("Engine C (NLP)", inferenceTimeMs, actualRiskScore)
        TelemetryManager.logNLPEvent(predictedLabel, confidence)

        if (!isSilent) {
            _nlpEvents.tryEmit("> ANALYSIS_COMPLETE: [$predictedLabel] CONFIDENCE: ${confidence.toInt()}%")
            _isAnalyzing.value = false
        }

        return@withContext Pair(predictedLabel, confidence)
    }

    suspend fun analyzeText(text: String): Float = withContext(NlpDispatcher) {
        val (label, confidencePct) = analyzePolicyClause(text, isSilent = false)
        if (label == "Error") return@withContext 0f
        return@withContext calculateActualRisk(label, confidencePct)
    }

    suspend fun analyzePolicyClauses(texts: List<String>): List<Pair<String, Float>> = withContext(NlpDispatcher) {
        texts
            .filter { it.isNotBlank() && it.length >= 10 }
            .map { async { analyzePolicyClause(it, isSilent = true) } }
            .awaitAll()
    }

    private fun softmaxInPlace(logits: FloatArray) {
        var maxLogit = Float.NEGATIVE_INFINITY
        for (logit in logits) {
            if (logit > maxLogit) maxLogit = logit
        }
        var sumExp = 0f
        for (i in logits.indices) {
            val e = exp((logits[i] - maxLogit).toDouble()).toFloat()
            logits[i] = e
            sumExp += e
        }
        for (i in logits.indices) {
            logits[i] /= sumExp
        }
    }

    fun shutdown() {
        managerScope.launch(NlpDispatcher) {
            engineLock.writeLock().lock()
            try {
                shutdownInternal()
            } finally {
                engineLock.writeLock().unlock()
            }
        }
    }

    private fun shutdownInternal() {
        try {
            if (!bootDeferred.isCompleted) bootDeferred.cancel()
            ortSession?.close()
            ortEnv?.close()
            ortSession = null
            ortEnv = null
            tokenizer = null
            labelMapping = null
            isInitialized = false
            isBooting.set(false)
            Log.d(TAG, "🛑 Engine C Offline: Matrix violently purged from RAM.")
            TelemetryManager.logToTerminal("SYS", "Auditor Disabled: NLP Matrix unloaded from RAM.")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error during shutdown", e)
        }
    }

    fun isReady(): Boolean = isInitialized && ortSession != null
}