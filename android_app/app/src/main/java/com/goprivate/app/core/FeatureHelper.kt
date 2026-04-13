package com.goprivate.app.core

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Utility to load the exact Machine Learning feature configurations from assets.
 */
object FeatureHelper {
    private const val TAG = "FeatureHelper"

    /**
     * Reads a JSON array of strings from the assets folder.
     * Crucial for maintaining the exact mathematical shape of the ONNX tensors.
     */
    fun loadFeatureNames(context: Context, fileName: String): List<String> {
        return try {
            // .use {} automatically closes the InputStream, preventing memory leaks
            context.assets.open(fileName).bufferedReader().use { reader ->
                val jsonString = reader.readText()
                val type = object : TypeToken<List<String>>() {}.type
                Gson().fromJson(jsonString, type)
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to load feature names from $fileName", e)
            emptyList()
        }
    }
}