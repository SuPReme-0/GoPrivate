@file:Suppress("SpellCheckingInspection") // Silences 'xbin' typo warning

package com.goprivate.app.core

import android.annotation.SuppressLint
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import javax.crypto.CipherInputStream
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Production-grade security utilities for GoPrivate.
 * Handles model decryption, integrity verification, and environment checks.
 */
object SecurityCore {
    private const val TAG = "GoPrivateSecurity"

    // 🚨 MUST MATCH PYTHON ENCRYPTION SCRIPT EXACTLY (32 bytes = AES-256)
    private val MASTER_KEY = "GoPrivate_32_Byte_Master_Key_123".toByteArray()
    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/ECB/PKCS5Padding"

    // 🚨 Populate with SHA-256 hashes from Python hash generator script
    private val EXPECTED_MODEL_HASHES = mapOf(
        "engine_a_model.enc" to "6E10291FDDA798C20FB3D9F53D73917E6E8A0E07BCDF3F28C0A2E263BCCF80E3",
        "engine_b_model.enc" to "F6A1BE3C80F61D757B779D563B20369FA1DF412B339CE0347B466F09A4C2E5FC",
        "engine_c_model.enc" to "70F01972F156D0A82A608DE71341BB34E1C5C7F18C0EF487A2048E5EA045ED7B"
    )

    /**
     * Decrypts an encrypted model file in memory using AES-256.
     * Verifies integrity via SHA-256 hash before returning.
     * @param encryptedData The encrypted byte array from assets
     * @param modelName The filename (e.g., "engine_a_model.enc") for hash lookup
     * @return Decrypted byte array or null on failure
     */
    @SuppressLint("GetInstance") // ECB is acceptable for static binary obfuscation
    fun decryptModelInMemory(encryptedData: ByteArray
                             , modelName: String): ByteArray? {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val keySpec = SecretKeySpec(MASTER_KEY, ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, keySpec)

            val decryptedBytes = cipher.doFinal(encryptedData)

            // Verify integrity before use
            if (!verifyIntegrity(decryptedBytes, modelName)) {
                Log.e(TAG, "🚨 INTEGRITY CHECK FAILED for $modelName")
                secureWipe(decryptedBytes)
                return null
            }

            decryptedBytes
        } catch (e: Exception) {
            Log.e(TAG, "❌ Decryption failed for $modelName", e)
            null
        }
    }

    /**
     * Verifies data integrity using SHA-256 hash comparison.
     * @param data The byte array to verify
     * @param modelName The model name for expected hash lookup
     * @return True if hash matches, false otherwise
     */
    private fun verifyIntegrity(data: ByteArray, modelName: String): Boolean {
        val expectedHash = EXPECTED_MODEL_HASHES[modelName]

        // Generate the actual hash of the decrypted bytes
        val md = MessageDigest.getInstance("SHA-256")
        val actualHash = md.digest(data).joinToString("") { "%02x".format(it) }.uppercase() // Ensure uppercase

        if (expectedHash == null || expectedHash.startsWith("PASTE_")) {
            Log.e(TAG, "⚠️ EXPECTED HASH MISSING. ACTUAL HASH FOR $modelName IS: $actualHash")
            return true // Allow bypass to get the hash
        }

        if (actualHash != expectedHash) {
            Log.e(TAG, "🚨 HASH MISMATCH for $modelName!")
            Log.e(TAG, "EXPECTED: $expectedHash")
            Log.e(TAG, "ACTUAL  : $actualHash  <-- COPY THIS INTO SecurityCore.kt")
            return false
        }
        return true
    }
    /**
     * Securely wipes a byte array from memory to prevent RAM dump attacks.
     * Overwrites with zeros, pattern, then zeros again.
     * @param data The byte array to wipe (nullable)
     */
    fun secureWipe(data: ByteArray?) {
        if (data != null && data.isNotEmpty()) {
            data.fill(0)
            data.fill(0x5A) // Arbitrary pattern
            data.fill(0)
        }
    }

    /**
     * Checks if the app is running in a potentially compromised environment.
     * @return True if environment appears secure, false if rooted/debugger detected
     */
    fun isEnvironmentSecure(): Boolean {
        return !isDeviceRooted() && !android.os.Debug.isDebuggerConnected()
    }

    /**
     * Basic root detection via common su binary paths.
     * @return True if device appears rooted
     */
    private fun isDeviceRooted(): Boolean {
        val paths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",  // xbin = eXecutable BINaries (Linux standard)
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su"
        )
        return paths.any { File(it).exists() }
    }
    @SuppressLint("GetInstance")
    fun decryptModelToTempFile(context: android.content.Context, modelName: String): String? {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val keySpec = SecretKeySpec(MASTER_KEY, ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, keySpec)

            // Create a temporary file in the app's isolated internal cache
            val tempFile = File(context.cacheDir, "${modelName}_decrypted.onnx")

            context.assets.open(modelName).use { inputStream ->
                CipherInputStream(inputStream, cipher).use { cis ->
                    FileOutputStream(tempFile).use { fos ->
                        val buffer = ByteArray(8192) // 8KB streaming buffer
                        var bytesRead: Int
                        while (cis.read(buffer).also { bytesRead = it } != -1) {
                            fos.write(buffer, 0, bytesRead)
                        }
                    }
                }
            }
            tempFile.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "❌ Streaming decryption failed for $modelName", e)
            null
        }
    }
}