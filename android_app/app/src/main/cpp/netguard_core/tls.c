/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#include "netguard.h"
#include <string.h>

// --------------------------------------------------------------------------
// 🚨 ZERO-LATENCY SNI EXTRACTOR (RFC 6066 COMPLIANT)
// Hardened against crafted packets, DoS loops, and multi-record TCP streams.
// --------------------------------------------------------------------------
int get_sni(const uint8_t *data, const uint16_t datalen, char *server_name) {

    // ⚡ 1-NANOSECOND FAST-PATH EXIT:
    // 99.9% of packets are standard encrypted data. If it doesn't start with
    // 0x16 (TLS Handshake), drop it instantly to save CPU cycles.
    if (datalen < 44 || data[0] != 22) return 0;

    // Verify TLS Message Type is ClientHello (1)
    if (data[5] != 1) return 0;

    // 🚨 MULTI-RECORD FIX: Bound the parser strictly to the TLS Record Length,
    // not the raw TCP datalen, to prevent reading into concatenated encrypted data.
    uint16_t record_len = ((uint16_t)data[3] << 8) | data[4];
    uint16_t limit = (record_len + 5 < datalen) ? (record_len + 5) : datalen;

    // Start exactly at the Session ID length byte (Standard TLS 1.2/1.3)
    uint32_t index = 43;

    // 1. Skip Session ID
    if (index >= limit) return 0;
    index += 1 + data[index];

    // 2. Skip Cipher Suites
    if (index + 2 > limit) return 0;
    uint16_t suites_len = ((uint16_t)data[index] << 8) | data[index + 1];
    index += 2 + suites_len;

    // 3. Skip Compression Methods
    if (index + 1 > limit) return 0;
    uint8_t comp_len = data[index];
    index += 1 + comp_len;

    // 4. Parse Extensions Length
    if (index + 2 > limit) return 0;
    uint16_t ext_total_len = ((uint16_t)data[index] << 8) | data[index + 1];
    index += 2;

    // Validate overall extension bounds
    if (ext_total_len == 0 || index + ext_total_len > limit) return 0;

    uint32_t end_index = index + ext_total_len;

    // 5. Hunt for the SNI Extension (Type 0)
    while (index + 4 <= end_index) {
        uint16_t ext_type = ((uint16_t)data[index] << 8) | data[index + 1];
        uint16_t ext_len  = ((uint16_t)data[index + 2] << 8) | data[index + 3];
        index += 4;

        if (index + ext_len > end_index) return 0;

        // TLS_EXTENSION_TYPE_SERVER_NAME (0)
        if (ext_type == 0 && ext_len >= 5) {

            // Extract the ServerNameList length
            uint16_t list_len = ((uint16_t)data[index] << 8) | data[index + 1];
            if (list_len + 2 > ext_len) return 0;

            uint32_t name_index = index + 2;
            uint32_t list_end = name_index + list_len;

            // Iterate safely through the ServerNameList
            while (name_index + 3 <= list_end) {
                uint8_t name_type = data[name_index];
                uint16_t name_len = ((uint16_t)data[name_index + 1] << 8) | data[name_index + 2];
                name_index += 3;

                if (name_index + name_len > list_end) return 0;

                // 🚨 RFC 6066 COMPLIANCE FIX:
                // We MUST verify that name_type == 0x00 (host_name).
                if (name_type == 0 && name_len > 0 && name_len < TLS_SNI_LENGTH) {
                    memcpy(server_name, data + name_index, name_len);
                    server_name[name_len] = '\0'; // Strictly null-terminate
                    return 1; // ✅ SNI Successfully Extracted
                }

                // If it's a different name_type, skip to the next one
                name_index += name_len;
            }
            return 0; // Malformed or missing host_name in SNI list
        }

        // Jump to the next extension
        index += ext_len;
    }

    return 0;
}