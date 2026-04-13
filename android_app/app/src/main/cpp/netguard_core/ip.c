/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#include "netguard.h"

int max_tun_msg = 0;
extern int loglevel;
extern FILE *pcap_file;

// 🚨 THE MTU FIX: Matches Kotlin's builder.setMtu(1500)
uint16_t get_mtu() {
    return 1500;
}

uint16_t get_default_mss(int version) {
    if (version == 4)
        return (uint16_t) (get_mtu() - sizeof(struct iphdr) - sizeof(struct tcphdr));
    else
        return (uint16_t) (get_mtu() - sizeof(struct ip6_hdr) - sizeof(struct tcphdr));
}

int check_tun(const struct arguments *args,
              const struct epoll_event *ev,
              const int epoll_fd,
              int sessions, int maxsessions) {

    if (ev->events & EPOLLERR) {
        if (fcntl(args->tun, F_GETFL) < 0) {
            report_exit(args, "fcntl tun %d F_GETFL error %d: %s", args->tun, errno, strerror(errno));
        }
        return -1;
    }

    if (ev->events & EPOLLIN) {
        // 🚨 ZERO-ALLOCATION HOT PATH
        static __thread uint8_t buffer[65536];

        ssize_t length = read(args->tun, buffer, get_mtu());

        if (length < 0) {
            if (errno == EINTR || errno == EAGAIN) return 0;
            return -1;
        } else if (length > 0) {

            if (pcap_file != NULL) write_pcap_rec(buffer, (size_t) length);
            if (length > max_tun_msg) max_tun_msg = length;

            // ------------------------------------------------------------------
            // 🚨 GOPRIVATE ML GATEKEEPER: UNIVERSAL BYTE-PARSER
            // ------------------------------------------------------------------
            uint8_t version = buffer[0] >> 4;
            int protocol = 0, srcPort = 0, destPort = 0, headerSize = 0, tcpFlags = 0, is_new_flow = 0, is_valid = 0;
            char src_ip[INET6_ADDRSTRLEN] = {0}, dst_ip[INET6_ADDRSTRLEN] = {0};

            if (version == 4) {
                headerSize = (buffer[0] & 0x0F) * 4;
                if (length >= headerSize) {
                    protocol = buffer[9];
                    inet_ntop(AF_INET, buffer + 12, src_ip, sizeof(src_ip));
                    inet_ntop(AF_INET, buffer + 16, dst_ip, sizeof(dst_ip));
                    is_valid = 1;
                }
            } else if (version == 6) {
                headerSize = 40; // IPv6 Base Header
                if (length >= headerSize) {
                    protocol = buffer[6]; // Next Header
                    
                    // 🚨 FAST-PATH IPv6 EXTENSION SKIPPING: Prevents Meta from hiding ports
                    int ext_count = 0;
                    while ((protocol == 0 || protocol == 60 || protocol == 43 || protocol == 44 || protocol == 51 || protocol == 50 || protocol == 135) && length >= headerSize + 8) {
                        if (++ext_count > 4) break;
                        protocol = buffer[headerSize];
                        headerSize += 8 + buffer[headerSize + 1];
                    }

                    if (length >= headerSize) {
                        inet_ntop(AF_INET6, buffer + 8, src_ip, sizeof(src_ip));
                        inet_ntop(AF_INET6, buffer + 24, dst_ip, sizeof(dst_ip));
                        is_valid = 1;
                    }
                }
            }

            if (is_valid) {
                if (protocol == IPPROTO_TCP && length >= headerSize + 20) {
                    uint16_t *sport_ptr = (uint16_t *)(buffer + headerSize);
                    uint16_t *dport_ptr = (uint16_t *)(buffer + headerSize + 2);
                    srcPort = ntohs(*sport_ptr);
                    destPort = ntohs(*dport_ptr);
                    
                    int tcp_data_offset = (buffer[headerSize + 12] >> 4) * 4;
                    tcpFlags = buffer[headerSize + 13];
                    headerSize += tcp_data_offset;

                    // Trigger Kotlin on Connection Start (SYN) or Reset (RST)
                    if ((tcpFlags & 0x02) || (tcpFlags & 0x04)) is_new_flow = 1;
                    
                } else if (protocol == IPPROTO_UDP && length >= headerSize + 8) {
                    uint16_t *sport_ptr = (uint16_t *)(buffer + headerSize);
                    uint16_t *dport_ptr = (uint16_t *)(buffer + headerSize + 2);
                    srcPort = ntohs(*sport_ptr);
                    destPort = ntohs(*dport_ptr);
                    headerSize += 8;

                    // 🚨 INSTAGRAM FIX: Intercept UDP 443 (QUIC) and UDP 53 (DNS)
                    if (destPort == 53 || destPort == 443 || srcPort == 443) is_new_flow = 1;
                }

                // ⚡ Cross the JNI Bridge
                if (is_new_flow && srcPort != 0 && destPort != 0) {
                    if (!fire_kotlin_interceptor(src_ip, srcPort, dst_ip, destPort, protocol, (int)length, headerSize, tcpFlags)) {
                        return 0; // 🛑 INSTAGRAM / QUIC / IPv6 VAPORIZED
                    }
                }
            }
            // ------------------------------------------------------------------
            // END OF GOPRIVATE ML GATEKEEPER
            // ------------------------------------------------------------------

            handle_ip(args, buffer, (size_t) length, epoll_fd, sessions, maxsessions);

        } else {
            return -1;
        }
    }

    return 0;
}

int is_lower_layer(int protocol) {
    return (protocol == 0 || protocol == 60 || protocol == 43 || protocol == 44 || protocol == 51 || protocol == 50 || protocol == 135);
}

int is_upper_layer(int protocol) {
    return (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6);
}

void handle_ip(const struct arguments *args,
               const uint8_t *pkt, const size_t length,
               const int epoll_fd,
               int sessions, int maxsessions) {
    uint8_t protocol;
    void *saddr;
    void *daddr;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    char flags[10];
    char data[16];
    int flen = 0;
    uint8_t *payload;

    uint8_t version = (*pkt) >> 4;

    // ==========================================================================
    // 🚨 LAYER 3 STATEFUL IPS BLOCK (IP / IPv6)
    // ==========================================================================
    if (version == 4) {
        if (length < sizeof(struct iphdr)) {
            fire_threat_alert("Malformed IPv4 Header", "Unknown", 0);
            return;
        }

        struct iphdr *ip4hdr = (struct iphdr *) pkt;

        if (ip4hdr->ihl < 5) {
            fire_threat_alert("Invalid IPv4 Header Length", "Unknown", 0);
            return;
        }

        protocol = ip4hdr->protocol;
        saddr = &ip4hdr->saddr;
        daddr = &ip4hdr->daddr;

        inet_ntop(AF_INET, saddr, source, sizeof(source));
        inet_ntop(AF_INET, daddr, dest, sizeof(dest));

        // 🚨 ENDIANNESS FIX APPLIED: Safe fragmentation check
        uint16_t frag_off_host = ntohs(ip4hdr->frag_off);
        if ((frag_off_host & IP_MF) || (frag_off_host & IP_OFFMASK)) {
            fire_threat_alert("Fragmented Packet Exploit Blocked", source, 0);
            return;
        }

        uint8_t ipoptlen = (uint8_t) ((ip4hdr->ihl - 5) * 4);
        payload = (uint8_t *) (pkt + sizeof(struct iphdr) + ipoptlen);

        // 🚨 OS PADDING FIX APPLIED: Drop if truncated, allow if padded
        if (length < ntohs(ip4hdr->tot_len)) {
            fire_threat_alert("Packet Length Truncated (Overflow Attempt)", source, 0);
            return;
        }

        uint32_t src_ip_raw = ntohl(ip4hdr->saddr);
        if ((src_ip_raw & 0xFF000000) == 0x7F000000) {
            uint32_t dst_ip_raw = ntohl(ip4hdr->daddr);
            if ((dst_ip_raw & 0xFF000000) != 0x7F000000) {
                fire_threat_alert("IPv4 Bogon Spoofing Blocked", source, 0);
                return;
            }
        }

    } else if (version == 6) {
        if (length < sizeof(struct ip6_hdr)) return;

        struct ip6_hdr *ip6hdr = (struct ip6_hdr *) pkt;
        uint16_t off = 0;
        protocol = ip6hdr->ip6_nxt;

        int ext_count = 0;
        if (!is_upper_layer(protocol)) {
            off = sizeof(struct ip6_hdr);
            struct ip6_ext *ext = (struct ip6_ext *) (pkt + off);
            while (is_lower_layer(ext->ip6e_nxt) && !is_upper_layer(protocol)) {
                if (++ext_count > 4) {
                    fire_threat_alert("IPv6 Extension Header DoS Blocked", "Unknown", 0);
                    return;
                }
                protocol = ext->ip6e_nxt;
                off += (8 + ext->ip6e_len);
                if (off > length) return;
                ext = (struct ip6_ext *) (pkt + off);
            }
            if (!is_upper_layer(protocol)) {
                off = 0;
                protocol = ip6hdr->ip6_nxt;
            }
        }

        saddr = &ip6hdr->ip6_src;
        daddr = &ip6hdr->ip6_dst;
        payload = (uint8_t *) (pkt + sizeof(struct ip6_hdr) + off);

        inet_ntop(AF_INET6, saddr, source, sizeof(source));
        inet_ntop(AF_INET6, daddr, dest, sizeof(dest));

        if (IN6_IS_ADDR_LOOPBACK((struct in6_addr*)saddr) && !IN6_IS_ADDR_LOOPBACK((struct in6_addr*)daddr)) {
            fire_threat_alert("IPv6 Bogon Spoofing Blocked", source, 0);
            return;
        }

    } else {
        return;
    }

    // ==========================================================================
    // 🚨 LAYER 4 STATEFUL IPS BLOCK & ROUTING (TCP/UDP/ICMP)
    // ==========================================================================

    int syn = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    *data = 0;

    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
        if (length - (payload - pkt) < ICMP_MINLEN) return;
        struct icmp *icmp = (struct icmp *) payload;
        sprintf(data, "type %d/%d", icmp->icmp_type, icmp->icmp_code);
        sport = ntohs(icmp->icmp_id);
        dport = ntohs(icmp->icmp_id);
    } else if (protocol == IPPROTO_UDP) {
        if (length - (payload - pkt) < sizeof(struct udphdr)) return;
        struct udphdr *udp = (struct udphdr *) payload;
        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);

        if (sport == 0) {
            fire_threat_alert("Malformed UDP (Port 0)", source, dport);
            return;
        }

    } else if (protocol == IPPROTO_TCP) {
        if (length - (payload - pkt) < sizeof(struct tcphdr)) return;
        struct tcphdr *tcp = (struct tcphdr *) payload;
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);

        if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg) {
            fire_threat_alert("TCP NULL Port Scan Blocked", source, dport);
            return;
        }

        if (tcp->fin && tcp->psh && tcp->urg) {
            fire_threat_alert("TCP XMAS Port Scan Blocked", source, dport);
            return;
        }

        if (tcp->syn && tcp->fin) {
            fire_threat_alert("TCP SYN-FIN State Anomaly Blocked", source, dport);
            return;
        }

        if (tcp->syn) { syn = 1; flags[flen++] = 'S'; }
        if (tcp->ack) flags[flen++] = 'A';
        if (tcp->psh) flags[flen++] = 'P';
        if (tcp->fin) flags[flen++] = 'F';
        if (tcp->rst) flags[flen++] = 'R';
    }

    flags[flen] = 0;

    if (sessions >= maxsessions) {
        if ((protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) ||
            (protocol == IPPROTO_UDP && !has_udp_session(args, pkt, payload)) ||
            (protocol == IPPROTO_TCP && syn)) {
            return;
        }
    }

    jint uid = -1;
    char server_name[TLS_SNI_LENGTH + 1];
    *server_name = 0;

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcphdr = (struct tcphdr *) payload;
        const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
        const uint8_t *tls_data = payload + sizeof(struct tcphdr) + tcpoptlen;
        const uint16_t datalen = (const uint16_t) (length - (tls_data - pkt));

        if (get_sni(tls_data, datalen, server_name)) {
            uid = get_uid(version, protocol, saddr, sport, daddr, dport);
        }
    }

    if (*server_name != 0) strcpy(data, "sni");

    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6 ||
        (protocol == IPPROTO_UDP && !has_udp_session(args, pkt, payload)) ||
        (protocol == IPPROTO_TCP && syn)) {
        uid = get_uid_q(args, version, protocol, source, sport, dest, dport);
    }

    int allowed = 0;
    struct allowed *redirect = NULL;

    if (protocol == IPPROTO_UDP && has_udp_session(args, pkt, payload)) allowed = 1;
    else if (protocol == IPPROTO_TCP && (!syn || (uid == 0 && dport == 53)) && *server_name == 0) allowed = 1;
    else {
        jobject objPacket = create_packet(args, version, protocol, flags, source, sport, dest, dport, data, uid, 0);
        redirect = is_address_allowed(args, objPacket);
        allowed = (redirect != NULL);
        if (redirect != NULL && (*redirect->raddr == 0 || redirect->rport == 0)) redirect = NULL;
    }

    if (allowed) {
        if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) handle_icmp(args, pkt, length, payload, uid, epoll_fd);
        else if (protocol == IPPROTO_UDP) handle_udp(args, pkt, length, payload, uid, redirect, epoll_fd);
        else if (protocol == IPPROTO_TCP) handle_tcp(args, pkt, length, payload, uid, allowed, redirect, epoll_fd);
    } else {
        if (protocol == IPPROTO_UDP) block_udp(args, pkt, length, payload, uid);
        else if (protocol == IPPROTO_TCP && *server_name != 0 && !allowed) handle_tcp(args, pkt, length, payload, uid, allowed, redirect, epoll_fd);
    }
}

jint get_uid(const int version, const int protocol, const void *saddr, const uint16_t sport, const void *daddr, const uint16_t dport) {
    jint uid = -1;
    char source[INET6_ADDRSTRLEN + 1], dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, saddr, source, sizeof(source));
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));

    struct timeval time;
    gettimeofday(&time, NULL);
    long now = (time.tv_sec * 1000) + (time.tv_usec / 1000);

    if (version == 4) {
        uint8_t saddr128[16];
        memset(saddr128, 0, 10);
        saddr128[10] = 0xFF; saddr128[11] = 0xFF;
        memcpy(saddr128 + 12, saddr, 4);

        uint8_t daddr128[16];
        memset(daddr128, 0, 10);
        daddr128[10] = 0xFF; daddr128[11] = 0xFF;
        memcpy(daddr128 + 12, daddr, 4);

        uid = get_uid_sub(6, protocol, saddr128, sport, daddr128, dport, source, dest, now);
    }

    if (uid == -1) uid = get_uid_sub(version, protocol, saddr, sport, daddr, dport, source, dest, now);
    return uid;
}

int uid_cache_size = 0;
struct uid_cache_entry *uid_cache = NULL;

jint get_uid_sub(const int version, const int protocol,
                 const void *saddr, const uint16_t sport,
                 const void *daddr, const uint16_t dport,
                 const char *source, const char *dest,
                 long now) {

    static uint8_t zero[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int ws = (version == 4 ? 1 : 4);

    for (int i = 0; i < uid_cache_size; i++) {
        if (now - uid_cache[i].time <= UID_MAX_AGE &&
            uid_cache[i].version == version &&
            uid_cache[i].protocol == protocol &&
            uid_cache[i].sport == sport &&
            (uid_cache[i].dport == dport || uid_cache[i].dport == 0) &&
            (memcmp(uid_cache[i].saddr, saddr, (size_t) (ws * 4)) == 0 || memcmp(uid_cache[i].saddr, zero, (size_t) (ws * 4)) == 0) &&
            (memcmp(uid_cache[i].daddr, daddr, (size_t) (ws * 4)) == 0 || memcmp(uid_cache[i].daddr, zero, (size_t) (ws * 4)) == 0)) {
            return uid_cache[i].uid;
        }
    }

    return -1;
}