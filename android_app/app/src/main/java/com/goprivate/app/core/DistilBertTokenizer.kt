@file:Suppress("SpellCheckingInspection")

package com.goprivate.app.core

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader

class DistilBertTokenizer(context: Context) {
    private val vocab = mutableMapOf<String, Int>()

    // Moved to a companion object. This fixes the naming warnings and
    // prevents memory duplication if you ever create multiple tokenizers.
    companion object {
        private const val TAG = "DistilBertTokenizer"
        private const val CLS_ID = 101
        private const val SEP_ID = 102
        private const val UNK_ID = 100
        private const val MAX_LENGTH = 128 // Perfectly aligned with Engine C's tensor shape
    }

    init {
        loadVocab(context)
    }

    /**
     * Loads the vocab.txt file from assets into a Hash Map for O(1) lookups.
     */
    private fun loadVocab(context: Context) {
        try {
            val inputStream = context.assets.open("vocab.txt")
            val reader = BufferedReader(InputStreamReader(inputStream))
            var index = 0
            reader.forEachLine { line ->
                vocab[line] = index
                index++
            }
            Log.d(TAG, "✅ Loaded ${vocab.size} tokens from vocab.txt")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to load vocab.txt", e)
        }
    }

    /**
     * Converts a raw string sentence into the exact Int64 arrays ONNX expects.
     * Returns a Pair: (Input IDs, Attention Mask)
     */
    fun tokenize(text: String): Pair<LongArray, LongArray> {
        val tokens = mutableListOf<Int>()
        tokens.add(CLS_ID) // Always start with [CLS]

        // OPTIMIZED: Pad punctuation with spaces instead of deleting it
        val cleanText = text.lowercase()
            .replace(Regex("([.,!?()\\-\"'])"), " $1 ")
            .replace(Regex("\\s+"), " ") // Remove extra spaces
            .trim()

        val words = cleanText.split(" ").filter { it.isNotEmpty() }

        // WordPiece Sub-word tokenization
        for (word in words) {
            var currentWord = word
            var isUnknown = false
            val subTokens = mutableListOf<Int>()

            while (currentWord.isNotEmpty()) {
                var matchFound = false
                // Greedy longest-match search
                for (i in currentWord.length downTo 1) {
                    val subStr = currentWord.substring(0, i)
                    val searchStr = if (currentWord == word) subStr else "##$subStr"

                    if (vocab.containsKey(searchStr)) {
                        subTokens.add(vocab[searchStr]!!)
                        currentWord = currentWord.substring(i)
                        matchFound = true
                        break
                    }
                }
                if (!matchFound) {
                    isUnknown = true
                    break
                }
            }

            if (isUnknown) {
                tokens.add(UNK_ID)
            } else {
                tokens.addAll(subTokens)
            }
        }

        tokens.add(SEP_ID) // Always end text with [SEP]

        // LongArray natively initializes with 0s (which perfectly matches the [PAD] ID)
        val inputIds = LongArray(MAX_LENGTH)
        val attentionMask = LongArray(MAX_LENGTH)

        val actualSize = minOf(tokens.size, MAX_LENGTH)

        for (i in 0 until actualSize) {
            inputIds[i] = tokens[i].toLong()
            attentionMask[i] = 1L // 1 indicates pay attention (real word)
        }

        // 🚨 CRITICAL TRUNCATION FIX
        // If the text was too long, the [SEP] token got chopped off.
        // We MUST force the final token in the array to be the terminator.
        if (tokens.size > MAX_LENGTH) {
            inputIds[MAX_LENGTH - 1] = SEP_ID.toLong()
        }

        return Pair(inputIds, attentionMask)
    }
}