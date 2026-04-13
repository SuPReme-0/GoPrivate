package com.goprivate.app.core

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.BufferedReader
import java.io.InputStreamReader

object AssetHelper {
    private const val TAG = "GoPrivate_AssetHelper"

    /**
     * Reads a file from the assets folder and returns it as a String.
     */
    fun loadStringFromAsset(context: Context, fileName: String): String? {
        return try {
            val inputStream = context.assets.open(fileName)
            val bufferedReader = BufferedReader(InputStreamReader(inputStream))
            bufferedReader.use { it.readText() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load $fileName from assets", e)
            null
        }
    }

    /**
     * Specifically loads the Engine C Label Mapping JSON into a Kotlin Map.
     */
    fun loadEngineCLabelMapping(context: Context): Map<Int, String> {
        // IDE FIX: Using the Elvis operator (?:) for idiomatic Kotlin null-safety
        val jsonString = loadStringFromAsset(context, "engine_c_label_mapping.json") ?: return emptyMap()

        return try {
            val type = object : TypeToken<Map<String, String>>() {}.type
            val rawMap: Map<String, String> = Gson().fromJson(jsonString, type)

            rawMap.mapKeys { it.key.toInt() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse label mapping JSON", e)
            emptyMap()
        }
    }
}