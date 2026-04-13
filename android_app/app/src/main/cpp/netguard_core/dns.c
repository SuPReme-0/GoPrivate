/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#include "netguard.h"

// --------------------------------------------------------------------------
// 🚨 ZERO-LATENCY DNS NAME EXTRACTOR
// --------------------------------------------------------------------------
int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname) {
    *qname = 0;
    if (off >= datalen) return -1;

    uint16_t c = 0;
    uint8_t noff = 0;
    uint16_t ptr = off;
    uint8_t len = *(data + ptr);
    uint8_t count = 0;

    while (len) {
        // Security bounds: Prevent infinite loops from crafted pointer cycles
        if (count++ > 25) break;

        if (ptr + 1 < datalen && (len & 0xC0)) {
            uint16_t jump = (uint16_t) ((len & 0x3F) * 256 + *(data + ptr + 1));
            if (jump >= datalen) break;

            ptr = jump;
            len = *(data + ptr);

            if (!c) {
                c = 1;
                off += 2;
            }
        } else if (ptr + 1 + len < datalen && noff + len <= DNS_QNAME_MAX) {
            memcpy(qname + noff, data + ptr + 1, len);
            *(qname + noff + len) = '.';
            noff += (len + 1);

            uint32_t jump = (uint32_t) (ptr + 1 + len);
            if (jump >= datalen) break;

            ptr = jump;
            len = *(data + ptr);
        } else {
            break;
        }
    }
    ptr++;

    if (len > 0 || noff == 0) return -1;

    *(qname + noff - 1) = 0;
    return (c ? off : ptr);
}

// --------------------------------------------------------------------------
// 🚨 HIGH-SPEED DNS RESPONSE PARSER
// --------------------------------------------------------------------------
void parse_dns_response(const struct arguments *args, const struct ng_session *s, const uint8_t *data, size_t *datalen) {

    if (*datalen < sizeof(struct dns_header) + 1) return;

    struct dns_header *dns = (struct dns_header *) data;
    int qcount = ntohs(dns->q_count);
    int acount = ntohs(dns->ans_count);

    if (dns->qr == 1 && dns->opcode == 0 && qcount > 0 && acount > 0) {
        char name[DNS_QNAME_MAX + 1];
        int32_t off = sizeof(struct dns_header);

        uint16_t qtype = 0;
        uint16_t qclass = 0;
        char qname[DNS_QNAME_MAX + 1];

        // Parse Question
        for (int q = 0; q < 1; q++) {
            off = get_qname(data, *datalen, (uint16_t) off, name);
            if (off > 0 && off + 4 <= *datalen) {
                if (q == 0) {
                    strncpy(qname, name, DNS_QNAME_MAX);
                    qname[DNS_QNAME_MAX] = '\0';
                    qtype = ntohs(*((uint16_t *) (data + off)));
                    qclass = ntohs(*((uint16_t *) (data + off + 2)));
                }
                off += 4;
            } else return;
        }

        short svcb = 0;
        int32_t aoff = off;

        // Parse Answers
        for (int a = 0; a < acount; a++) {
            off = get_qname(data, *datalen, (uint16_t) off, name);
            if (off > 0 && off + 10 <= *datalen) {
                uint16_t a_qtype = ntohs(*((uint16_t *) (data + off)));
                uint16_t a_qclass = ntohs(*((uint16_t *) (data + off + 2)));
                uint32_t ttl = ntohl(*((uint32_t *) (data + off + 4)));
                uint16_t rdlength = ntohs(*((uint16_t *) (data + off + 8)));
                off += 10;

                if (off + rdlength <= *datalen) {
                    if (a_qclass == DNS_QCLASS_IN && (a_qtype == DNS_QTYPE_A || a_qtype == DNS_QTYPE_AAAA)) {
                        char rd[INET6_ADDRSTRLEN + 1];
                        if (a_qtype == DNS_QTYPE_A && off + sizeof(__be32) <= *datalen) {
                            inet_ntop(AF_INET, data + off, rd, sizeof(rd));
                        } else if (a_qclass == DNS_QCLASS_IN && a_qtype == DNS_QTYPE_AAAA && off + sizeof(struct in6_addr) <= *datalen) {
                            inet_ntop(AF_INET6, data + off, rd, sizeof(rd));
                        }
                        dns_resolved(args, qname, name, rd, ttl, -1);

                    } else if (a_qclass == DNS_QCLASS_IN && (a_qtype == DNS_SVCB || a_qtype == DNS_HTTPS)) {
                        svcb = 1;
                    }
                    off += rdlength;
                } else return;
            } else return;
        }

        // 🚨 KERNEL OVERRIDE: DNS Blackholing
        if (qcount > 0 && (svcb || is_domain_blocked(args, qname))) {
            dns->qr = 1;
            dns->aa = 0;
            dns->tc = 0;
            dns->rd = 0;
            dns->ra = 0;
            dns->z = 0;
            dns->ad = 0;
            dns->cd = 0;
            dns->rcode = (uint16_t) args->rcode;
            dns->ans_count = 0;
            dns->auth_count = 0;
            dns->add_count = 0;
            *datalen = aoff; // Truncate the packet
        }
    }
}