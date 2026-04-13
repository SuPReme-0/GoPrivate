/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#include "netguard.h"
#include <unistd.h>
#include <time.h>
#include <string.h>

// 🚨 GLOBALS
FILE *pcap_file = NULL;
size_t pcap_record_size = 64; // Snaplen (bytes to capture per packet)
long pcap_file_size = 2 * 1024 * 1024; // 2MB Max File Size

// --------------------------------------------------------------------------
// 🚨 PCAP INITIALIZATION
// --------------------------------------------------------------------------
void write_pcap_hdr() {
    if (pcap_file == NULL) return;

    struct pcap_hdr_s pcap_hdr;
    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = pcap_record_size;
    pcap_hdr.network = LINKTYPE_RAW; // Raw IP

    // Write the master header to initialize the file
    if (fwrite(&pcap_hdr, sizeof(struct pcap_hdr_s), 1, pcap_file) < 1) {
        log_android(ANDROID_LOG_ERROR, "PCAP Header fwrite error %d: %s", errno, strerror(errno));
    }
}

// --------------------------------------------------------------------------
// 🚨 ZERO-ALLOCATION FORENSIC LOGGING
// --------------------------------------------------------------------------
void write_pcap_rec(const uint8_t *buffer, size_t length) {
    if (pcap_file == NULL) return;

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts)) {
        return; // Silently abort on clock failure to preserve routing speed
    }

    size_t plen = (length < pcap_record_size ? length : pcap_record_size);

    // 1. Stack-Allocate the header (ZERO mallocs)
    struct pcaprec_hdr_s pcap_rec;
    pcap_rec.ts_sec = (guint32_t) ts.tv_sec;
    pcap_rec.ts_usec = (guint32_t) (ts.tv_nsec / 1000);
    pcap_rec.incl_len = (guint32_t) plen;
    pcap_rec.orig_len = (guint32_t) length;

    // 2. Sequential Buffered Writes (Eliminates memcpy and dynamic memory)
    // The C Standard Library (glibc) buffers these writes automatically.
    fwrite(&pcap_rec, sizeof(struct pcaprec_hdr_s), 1, pcap_file);
    fwrite(buffer, 1, plen, pcap_file);

    // 3. Size enforcement & Truncation
    long fsize = ftell(pcap_file);
    if (fsize > pcap_file_size) {
        // If the forensic log exceeds 2MB, truncate it back to just the master header.
        // This prevents the VPN from silently filling up the user's entire phone storage.
        if (ftruncate(fileno(pcap_file), sizeof(struct pcap_hdr_s)) == 0) {
            lseek(fileno(pcap_file), sizeof(struct pcap_hdr_s), SEEK_SET);
        } else {
            log_android(ANDROID_LOG_ERROR, "PCAP ftruncate error %d: %s", errno, strerror(errno));
        }
    }
}