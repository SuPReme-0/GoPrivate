@file:Suppress("unused", "SpellCheckingInspection")

package com.goprivate.app.core.network

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.sqrt

class FlowTracker(
    val sourceIpInt: Int,
    val destIpInt: Int,
    val destPort: Int,
    val protocol: Int = 6
) {
    private val startTimeMs = System.currentTimeMillis()
    private var lastPacketTimeMs = startTimeMs

    // Volumetric Trackers
    private var totalFwdPackets = 0
    private var totalBwdPackets = 0
    private var totalFwdBytes = 0L
    private var totalBwdBytes = 0L
    private var fwdHeaderLength = 0L
    private var bwdHeaderLength = 0L

    // TCP Flag Trackers
    private var synCount = 0
    private var ackCount = 0
    private var finCount = 0
    private var rstCount = 0
    private var pshCount = 0
    private var urgCount = 0

    // Pre-allocated Primitive Arrays
    private val packetLengths = IntArray(MAX_STORED_PACKETS)
    private val fwdPacketLengths = IntArray(MAX_STORED_PACKETS)
    private val bwdPacketLengths = IntArray(MAX_STORED_PACKETS)
    private val interArrivalTimes = LongArray(MAX_STORED_PACKETS)
    private val activeTimes = LongArray(MAX_STORED_PACKETS)
    private val idleTimes = LongArray(MAX_STORED_PACKETS)

    private var currentActiveStartTime = startTimeMs

    private var totalStoredCount = 0
    private var fwdStoredCount = 0
    private var bwdStoredCount = 0
    private var iatStoredCount = 0
    private var activeStoredCount = 0
    private var idleStoredCount = 0

    fun addPacket(
        packetSize: Int, headerSize: Int, flags: Int,
        isForward: Boolean, timestampMs: Long = System.currentTimeMillis()
    ) {
        if (totalStoredCount < MAX_STORED_PACKETS) packetLengths[totalStoredCount++] = packetSize

        if (isForward) {
            totalFwdPackets++
            totalFwdBytes += packetSize
            fwdHeaderLength += headerSize
            if (fwdStoredCount < MAX_STORED_PACKETS) fwdPacketLengths[fwdStoredCount++] = packetSize
        } else {
            totalBwdPackets++
            totalBwdBytes += packetSize
            bwdHeaderLength += headerSize
            if (bwdStoredCount < MAX_STORED_PACKETS) bwdPacketLengths[bwdStoredCount++] = packetSize
        }

        if (protocol == 6) {
            if ((flags and 0x02) != 0) synCount++
            if ((flags and 0x10) != 0) ackCount++
            if ((flags and 0x01) != 0) finCount++
            if ((flags and 0x04) != 0) rstCount++
            if ((flags and 0x08) != 0) pshCount++
            if ((flags and 0x20) != 0) urgCount++
        }

        val totalPackets = totalFwdPackets + totalBwdPackets
        if (totalPackets > 1) {
            val iat = timestampMs - lastPacketTimeMs
            if (iat >= 0 && iatStoredCount < MAX_STORED_PACKETS) interArrivalTimes[iatStoredCount++] = iat

            if (iat > IDLE_THRESHOLD_MS) {
                if (idleStoredCount < MAX_STORED_PACKETS) idleTimes[idleStoredCount++] = iat
                val activeTime = lastPacketTimeMs - currentActiveStartTime
                if (activeTime > 0 && activeStoredCount < MAX_STORED_PACKETS) activeTimes[activeStoredCount++] = activeTime
                currentActiveStartTime = timestampMs
            }
        }
        lastPacketTimeMs = timestampMs
    }

    private fun getDurationMicroseconds(): Float = ((System.currentTimeMillis() - startTimeMs) * 1000).toFloat()

    // ==========================================================================
    // 🚨 CPU THRASHING FIX: O(N) BATCH STATS CALCULATION
    // Calculates Mean, Min, Max, and StdDev in just 2 passes instead of 4.
    // ==========================================================================
    private fun extractIntStats(arr: IntArray, count: Int, out: FloatArray, meanIdx: Int, stdIdx: Int, maxIdx: Int, minIdx: Int) {
        if (count == 0) {
            out[meanIdx] = 0f; out[stdIdx] = 0f; out[maxIdx] = 0f; out[minIdx] = 0f
            return
        }
        var sum = 0L
        var min = arr[0]
        var max = arr[0]
        for (i in 0 until count) {
            val v = arr[i]
            sum += v
            if (v < min) min = v
            if (v > max) max = v
        }
        val mean = sum.toFloat() / count
        out[meanIdx] = mean
        out[minIdx] = min.toFloat()
        out[maxIdx] = max.toFloat()

        if (count > 1) {
            var sumSq = 0.0
            for (i in 0 until count) {
                val diff = arr[i] - mean
                sumSq += diff * diff
            }
            out[stdIdx] = sqrt(sumSq / count).toFloat()
        } else {
            out[stdIdx] = 0f
        }
    }

    private fun extractLongStats(arr: LongArray, count: Int, out: FloatArray, meanIdx: Int, stdIdx: Int, maxIdx: Int, minIdx: Int) {
        if (count == 0) {
            out[meanIdx] = 0f; out[stdIdx] = 0f; out[maxIdx] = 0f; out[minIdx] = 0f
            return
        }
        var sum = 0L
        var min = arr[0]
        var max = arr[0]
        for (i in 0 until count) {
            val v = arr[i]
            sum += v
            if (v < min) min = v
            if (v > max) max = v
        }
        val mean = sum.toFloat() / count
        out[meanIdx] = mean
        out[minIdx] = min.toFloat()
        out[maxIdx] = max.toFloat()

        if (count > 1) {
            var sumSq = 0.0
            for (i in 0 until count) {
                val diff = arr[i] - mean
                sumSq += diff * diff
            }
            out[stdIdx] = sqrt(sumSq / count).toFloat()
        } else {
            out[stdIdx] = 0f
        }
    }

    fun extractFeaturesToBuffer(outputBuffer: FloatArray) {
        val durMicro = getDurationMicroseconds()
        val durSecs = durMicro / 1_000_000f

        outputBuffer[0] = durMicro
        outputBuffer[1] = totalFwdPackets.toFloat()
        outputBuffer[2] = totalBwdPackets.toFloat()
        outputBuffer[3] = totalFwdBytes.toFloat()
        outputBuffer[4] = totalBwdBytes.toFloat()

        outputBuffer[5] = if (totalFwdPackets > 0) totalBwdPackets.toFloat() / totalFwdPackets.toFloat() else 0f
        outputBuffer[6] = fwdHeaderLength.toFloat()
        outputBuffer[7] = bwdHeaderLength.toFloat()

        // 🚨 O(N) FAST-PATH EXTRACTION (Preserves your original ONNX Array Alignments!)
        extractIntStats(packetLengths, totalStoredCount, outputBuffer, meanIdx = 8, stdIdx = 9, minIdx = 10, maxIdx = 11)
        outputBuffer[12] = if (totalFwdPackets + totalBwdPackets > 0) (totalFwdBytes + totalBwdBytes).toFloat() / (totalFwdPackets + totalBwdPackets).toFloat() else 0f

        extractIntStats(fwdPacketLengths, fwdStoredCount, outputBuffer, meanIdx = 13, stdIdx = 14, maxIdx = 15, minIdx = 16)
        extractIntStats(bwdPacketLengths, bwdStoredCount, outputBuffer, meanIdx = 17, stdIdx = 18, maxIdx = 19, minIdx = 20)

        extractLongStats(interArrivalTimes, iatStoredCount, outputBuffer, meanIdx = 21, stdIdx = 22, maxIdx = 23, minIdx = 24)
        extractLongStats(activeTimes, activeStoredCount, outputBuffer, meanIdx = 25, stdIdx = 26, maxIdx = 27, minIdx = 28)
        extractLongStats(idleTimes, idleStoredCount, outputBuffer, meanIdx = 29, stdIdx = 30, maxIdx = 31, minIdx = 32)

        outputBuffer[33] = synCount.toFloat()
        outputBuffer[34] = ackCount.toFloat()
        outputBuffer[35] = finCount.toFloat()
        outputBuffer[36] = rstCount.toFloat()
        outputBuffer[37] = pshCount.toFloat()
        outputBuffer[38] = urgCount.toFloat()

        outputBuffer[39] = if (durSecs > 0) (totalFwdBytes + totalBwdBytes).toFloat() / durSecs else 0f
        outputBuffer[40] = if (durSecs > 0) (totalFwdPackets + totalBwdPackets).toFloat() / durSecs else 0f
        outputBuffer[41] = if (durSecs > 0) totalFwdPackets.toFloat() / durSecs else 0f
        outputBuffer[42] = if (durSecs > 0) totalBwdPackets.toFloat() / durSecs else 0f

        outputBuffer[43] = protocol.toFloat()
        outputBuffer[44] = destPort.toFloat()
    }

    companion object {
        private const val MAX_STORED_PACKETS = 150
        private const val IDLE_THRESHOLD_MS = 5000L

        /**
         * 🚨 IPv6 TIMEBOMB DEACTIVATED
         * Instantly catches IPv6 strings (containing ':') and safely hashes them
         * to a 32-bit int, preventing fatal IndexOutOfBounds exceptions.
         */
        fun ipStringToInt(ipAddress: String): Int {
            if (ipAddress.contains(':')) return ipAddress.hashCode()

            var result = 0
            var current = 0
            var shift = 24
            for (i in ipAddress.indices) {
                val c = ipAddress[i]
                if (c == '.') {
                    result = result or (current shl shift)
                    shift -= 8
                    current = 0
                } else {
                    current = current * 10 + (c - '0')
                }
            }
            result = result or (current shl shift)
            return result
        }

        fun parsePacketHeader(buffer: ByteBuffer, length: Int, dest: ReusablePacketInfo): Boolean {
            if (length < 20) return false

            buffer.order(ByteOrder.BIG_ENDIAN)
            buffer.position(0)

            val versionAndIhl = buffer.get().toInt() and 0xFF
            if ((versionAndIhl shr 4) != 4) return false

            val ipIhl = (versionAndIhl and 0x0F) * 4
            if (length < ipIhl) return false

            dest.protocol = buffer.get(9).toInt() and 0xFF

            buffer.position(12)
            dest.sourceIpInt = buffer.int
            dest.destinationIpInt = buffer.int

            dest.packetSize = length
            dest.headerSize = ipIhl
            dest.tcpFlags = 0

            if (dest.protocol == 6 && length >= ipIhl + 20) {
                buffer.position(ipIhl)
                dest.sourcePort = buffer.short.toInt() and 0xFFFF
                dest.destinationPort = buffer.short.toInt() and 0xFFFF

                val tcpDataOffset = (buffer.get(ipIhl + 12).toInt() and 0xF0) shr 4
                dest.headerSize += tcpDataOffset * 4
                dest.tcpFlags = buffer.get(ipIhl + 13).toInt() and 0xFF
            }
            else if (dest.protocol == 17 && length >= ipIhl + 8) {
                buffer.position(ipIhl)
                dest.sourcePort = buffer.short.toInt() and 0xFFFF
                dest.destinationPort = buffer.short.toInt() and 0xFFFF
                dest.headerSize += 8
            } else {
                dest.sourcePort = 0
                dest.destinationPort = 0
            }

            return true
        }

        fun intToIpString(ipInt: Int): String {
            return "${(ipInt shr 24) and 0xFF}.${(ipInt shr 16) and 0xFF}.${(ipInt shr 8) and 0xFF}.${ipInt and 0xFF}"
        }
    }
}

class ReusablePacketInfo {
    var sourceIpInt: Int = 0
    var destinationIpInt: Int = 0
    var sourcePort: Int = 0
    var destinationPort: Int = 0
    var protocol: Int = 0
    var packetSize: Int = 0
    var headerSize: Int = 0
    var tcpFlags: Int = 0
}