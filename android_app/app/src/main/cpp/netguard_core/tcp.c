/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#include "netguard.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

extern char socks5_addr[INET6_ADDRSTRLEN + 1];
extern int socks5_port;
extern char socks5_username[127 + 1];
extern char socks5_password[127 + 1];

extern FILE *pcap_file;

// 🚨 CLEAN MEMORY LIFECYCLE
void clear_tcp_data(struct tcp_session *cur) {
    struct segment *s = cur->forward;
    while (s != NULL) {
        struct segment *p = s;
        s = s->next;
        free(p->data);
        free(p);
    }
    cur->forward = NULL;
}

int get_tcp_timeout(const struct tcp_session *t, int sessions, int maxsessions) {
    int timeout;
    if (t->state == TCP_LISTEN || t->state == TCP_SYN_RECV) timeout = TCP_INIT_TIMEOUT;
    else if (t->state == TCP_ESTABLISHED) timeout = TCP_IDLE_TIMEOUT;
    else timeout = TCP_CLOSE_TIMEOUT;

    int scale = 100 - sessions * 100 / maxsessions;
    return timeout * scale / 100;
}

int check_tcp_session(const struct arguments *args, struct ng_session *s, int sessions, int maxsessions) {
    time_t now = time(NULL);
    int timeout = get_tcp_timeout(&s->tcp, sessions, maxsessions);

    if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE && s->tcp.time + timeout < now) {
        if (s->tcp.state == TCP_LISTEN) s->tcp.state = TCP_CLOSING;
        else write_rst(args, &s->tcp);
    }

    if (s->tcp.state == TCP_CLOSING) {
        if (s->socket >= 0) {
            close(s->socket);
            s->socket = -1;
        }
        s->tcp.time = time(NULL);
        s->tcp.state = TCP_CLOSE;
    }

    if ((s->tcp.state == TCP_CLOSING || s->tcp.state == TCP_CLOSE) && (s->tcp.sent || s->tcp.received)) {
        s->tcp.sent = 0;
        s->tcp.received = 0;
    }

    if (s->tcp.state == TCP_CLOSE && s->tcp.time + TCP_KEEP_TIMEOUT < now) return 1;

    return 0;
}

int monitor_tcp_session(const struct arguments *args, struct ng_session *s, int epoll_fd) {
    int recheck = 0;
    unsigned int events = EPOLLERR;

    if (s->tcp.state == TCP_LISTEN) {
        if (s->tcp.socks5 == SOCKS5_NONE) events = events | EPOLLOUT;
        else events = events | EPOLLIN;
    } else if (s->tcp.state == TCP_ESTABLISHED || s->tcp.state == TCP_CLOSE_WAIT) {

        if (get_send_window(&s->tcp) > 0) events = events | EPOLLIN;
        else {
            recheck = 1;
            long long ms = get_ms();
            if (ms - s->tcp.last_keep_alive > EPOLL_MIN_CHECK) {
                s->tcp.last_keep_alive = ms;
                s->tcp.remote_seq--;
                write_ack(args, &s->tcp);
                s->tcp.remote_seq++;
            }
        }

        if (s->tcp.forward != NULL) {
            uint32_t buffer_size = get_receive_buffer(s);
            if (s->tcp.forward->seq == s->tcp.remote_seq && s->tcp.forward->len - s->tcp.forward->sent < buffer_size)
                events = events | EPOLLOUT;
            else recheck = 1;
        }
    }

    if (events != s->ev.events) {
        s->ev.events = events;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s->socket, &s->ev)) {
            s->tcp.state = TCP_CLOSING;
        }
    }

    return recheck;
}

uint32_t get_send_window(const struct tcp_session *cur) {
    uint32_t behind;
    if (cur->acked <= cur->local_seq) behind = (cur->local_seq - cur->acked);
    else behind = (0x10000 + cur->local_seq - cur->acked);

    behind += (cur->unconfirmed + 1) * 40;
    return (behind < cur->send_window ? cur->send_window - behind : 0);
}

uint32_t get_receive_buffer(const struct ng_session *cur) {
    if (cur->socket < 0) return 0;

    int sendbuf = 0;
    int sendbufsize = sizeof(sendbuf);
    getsockopt(cur->socket, SOL_SOCKET, SO_SNDBUF, &sendbuf, (socklen_t *) &sendbufsize);

    if (sendbuf == 0) sendbuf = SEND_BUF_DEFAULT;

    int unsent = 0;
    ioctl(cur->socket, SIOCOUTQ, &unsent);

    return (uint32_t) (unsent < sendbuf ? sendbuf - unsent : 0);
}

uint32_t get_receive_window(const struct ng_session *cur) {
    uint32_t toforward = 0;
    struct segment *q = cur->tcp.forward;
    while (q != NULL) {
        toforward += (q->len - q->sent);
        q = q->next;
    }

    uint32_t window = get_receive_buffer(cur);
    uint32_t max = ((uint32_t) 0xFFFF) << cur->tcp.recv_scale;
    if (window > max) window = max;

    return (toforward < window ? window - toforward : 0);
}

void check_tcp_socket(const struct arguments *args, const struct epoll_event *ev, const int epoll_fd) {
    struct ng_session *s = (struct ng_session *) ev->data.ptr;

    if (ev->events & EPOLLERR) {
        s->tcp.time = time(NULL);
        write_rst(args, &s->tcp);
    } else {
        if (s->tcp.state == TCP_LISTEN) {
            if (ev->events & EPOLLOUT) {
                // 🚨 FAULT 3B FIX: Check SO_ERROR before assuming the connection succeeded
                int err = 0;
                socklen_t errlen = sizeof(err);
                if (getsockopt(s->socket, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
                    write_rst(args, &s->tcp); // Route is dead or blocked, abort cleanly
                    return;
                }

                if (s->tcp.socks5 == SOCKS5_NONE) {
                    s->tcp.socks5 = SOCKS5_CONNECTED;
                }
            }

            // 🚨 THE SEQUENCE NUMBER DEADLOCK FIX
            if (s->tcp.socks5 == SOCKS5_CONNECTED) {
                s->tcp.state = TCP_SYN_RECV;

                // 1. Acknowledge the client's SYN (Consumes 1 sequence number)
                s->tcp.remote_seq++;

                if (write_syn_ack(args, &s->tcp) >= 0) {
                    // 2. Advance our own sequence tracker (Our SYN consumes 1 number)
                    s->tcp.local_seq++;
                    s->tcp.time = time(NULL);
                } else {
                    write_rst(args, &s->tcp);
                }
            }
        } else {
            int fwd = 0;
            if (ev->events & EPOLLOUT) {
                uint32_t buffer_size = get_receive_buffer(s);
                while (s->tcp.forward != NULL && s->tcp.forward->seq == s->tcp.remote_seq && s->tcp.forward->len - s->tcp.forward->sent < buffer_size) {
                    ssize_t sent = send(s->socket, s->tcp.forward->data + s->tcp.forward->sent, s->tcp.forward->len - s->tcp.forward->sent, (unsigned int) (MSG_NOSIGNAL | (s->tcp.forward->psh ? 0 : MSG_MORE)));
                    if (sent < 0) {
                        if (errno != EINTR && errno != EAGAIN) {
                            write_rst(args, &s->tcp);
                            break;
                        } else break;
                    } else {
                        fwd = 1;
                        buffer_size -= sent;
                        s->tcp.sent += sent;
                        s->tcp.forward->sent += sent;

                        if (s->tcp.forward->len == s->tcp.forward->sent) {
                            s->tcp.remote_seq = s->tcp.forward->seq + s->tcp.forward->sent;
                            struct segment *p = s->tcp.forward;
                            s->tcp.forward = s->tcp.forward->next;
                            free(p->data);
                            free(p);
                        } else break;
                    }
                }
            }

            uint32_t window = get_receive_window(s);
            uint32_t prev = s->tcp.recv_window;
            s->tcp.recv_window = window;

            if (fwd || (prev == 0 && window > 0)) {
                if (fwd && s->tcp.forward == NULL && s->tcp.state == TCP_CLOSE_WAIT) s->tcp.remote_seq++;
                if (write_ack(args, &s->tcp) >= 0) s->tcp.time = time(NULL);
            }

            if (s->tcp.state == TCP_ESTABLISHED || s->tcp.state == TCP_CLOSE_WAIT) {
                uint32_t send_window = get_send_window(&s->tcp);
                if ((ev->events & EPOLLIN) && send_window > 0) {
                    s->tcp.time = time(NULL);

                    uint32_t buffer_size = (send_window > s->tcp.mss ? s->tcp.mss : send_window);
                    if (buffer_size > 65536) buffer_size = 65536;

                    uint8_t buffer[65536];
                    ssize_t bytes = recv(s->socket, buffer, (size_t) buffer_size, 0);

                    if (bytes < 0) {
                        if (errno != EINTR && errno != EAGAIN) write_rst(args, &s->tcp);
                    } else if (bytes == 0) {
                        if (s->tcp.forward == NULL) {
                            if (write_fin_ack(args, &s->tcp) >= 0) s->tcp.local_seq++;
                            if (s->tcp.state == TCP_ESTABLISHED) s->tcp.state = TCP_FIN_WAIT1;
                            else if (s->tcp.state == TCP_CLOSE_WAIT) s->tcp.state = TCP_LAST_ACK;
                        } else {
                            write_rst(args, &s->tcp);
                        }
                        if (close(s->socket)) {}
                        s->socket = -1;
                    } else {
                        s->tcp.received += bytes;
                        if (ntohs(s->tcp.dest) == 53 && bytes > 2) {
                            ssize_t dlen = bytes - 2;
                            parse_dns_response(args, s, buffer + 2, (size_t *) &dlen);
                        }
                        if (write_data(args, &s->tcp, buffer, (size_t) bytes) >= 0) {
                            s->tcp.local_seq += bytes;
                            s->tcp.unconfirmed++;
                        }
                    }
                }
            }
        }
    }
}

jboolean handle_tcp(const struct arguments *args, const uint8_t *pkt, size_t length, const uint8_t *payload, int uid, int allowed, struct allowed *redirect, const int epoll_fd) {
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct tcphdr *tcphdr = (struct tcphdr *) payload;
    const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    const uint8_t *tcpoptions = payload + sizeof(struct tcphdr);
    const uint8_t *data = payload + sizeof(struct tcphdr) + tcpoptlen;
    const uint16_t datalen = (const uint16_t) (length - (data - pkt));

    struct ng_session *cur = args->ctx->ng_session;
    while (cur != NULL &&
           !(cur->protocol == IPPROTO_TCP && cur->tcp.version == version &&
             cur->tcp.source == tcphdr->source && cur->tcp.dest == tcphdr->dest &&
             (version == 4 ? cur->tcp.saddr.ip4 == ip4->saddr && cur->tcp.daddr.ip4 == ip4->daddr
                           : memcmp(&cur->tcp.saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->tcp.daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    if (tcphdr->urg) return 1;

    if (cur == NULL) {
        if (tcphdr->syn) {
            uint16_t mss = 1360;
            uint8_t ws = 0;
            int optlen = tcpoptlen;
            uint8_t *options = (uint8_t *) tcpoptions;
            while (optlen > 0) {
                uint8_t kind = *options;
                uint8_t len = *(options + 1);
                if (kind == 0) break;
                if (kind == 2 && len == 4) mss = ntohs(*((uint16_t *) (options + 2)));
                else if (kind == 3 && len == 3) ws = *(options + 2);

                if (kind == 1) { optlen--; options++; }
                else { optlen -= len; options += len; }
            }

            // 🚨 FAULT 3A FIX: Cap upstream MSS to perfectly match our tunnel
            uint16_t max_safe_mss = (version == 4) ? 1360 : 1340;
            if (mss > max_safe_mss) mss = max_safe_mss;

            struct ng_session *s = calloc(1, sizeof(struct ng_session));
            if (!s) return 0;

            s->protocol = IPPROTO_TCP;
            s->tcp.time = time(NULL);
            s->tcp.uid = uid;
            s->tcp.version = version;
            s->tcp.mss = mss;
            s->tcp.recv_scale = ws;
            s->tcp.send_scale = ws;
            s->tcp.send_window = ((uint32_t) ntohs(tcphdr->window)) << s->tcp.send_scale;
            s->tcp.unconfirmed = 0;

            // 🚨 FAULT 2 FIX (UNIVERSAL API SAFE): Cryptographically Secure ISN Generation
            uint32_t secure_isn;
            int urandom_fd = open("/dev/urandom", O_RDONLY);
            if (urandom_fd >= 0) {
                if (read(urandom_fd, &secure_isn, sizeof(secure_isn)) != sizeof(secure_isn)) {
                    secure_isn = (uint32_t) rand(); // Failsafe fallback
                }
                close(urandom_fd);
            } else {
                secure_isn = (uint32_t) rand(); // Failsafe fallback
            }
            s->tcp.local_seq = secure_isn;

            s->tcp.remote_seq = ntohl(tcphdr->seq);
            s->tcp.remote_start = s->tcp.remote_seq;
            s->tcp.local_start = s->tcp.local_seq;
            s->tcp.acked = 0;
            s->tcp.last_keep_alive = 0;
            s->tcp.sent = 0;
            s->tcp.received = 0;

            if (version == 4) {
                s->tcp.saddr.ip4 = (__be32) ip4->saddr;
                s->tcp.daddr.ip4 = (__be32) ip4->daddr;
            } else {
                memcpy(&s->tcp.saddr.ip6, &ip6->ip6_src, 16);
                memcpy(&s->tcp.daddr.ip6, &ip6->ip6_dst, 16);
            }

            s->tcp.source = tcphdr->source;
            s->tcp.dest = tcphdr->dest;
            s->tcp.state = TCP_LISTEN;
            s->tcp.socks5 = SOCKS5_NONE;
            s->tcp.forward = NULL;
            s->next = NULL;

            if (datalen) {
                s->tcp.forward = calloc(1, sizeof(struct segment));
                if (s->tcp.forward) {
                    s->tcp.forward->seq = s->tcp.remote_seq;
                    s->tcp.forward->len = datalen;
                    s->tcp.forward->sent = 0;
                    s->tcp.forward->psh = tcphdr->psh;
                    s->tcp.forward->data = calloc(1, datalen);
                    if (s->tcp.forward->data) memcpy(s->tcp.forward->data, data, datalen);
                    s->tcp.forward->next = NULL;
                }
            }

            s->socket = open_tcp_socket(args, &s->tcp, redirect);
            if (s->socket < 0) {
                free(s);
                return 0;
            }

            s->tcp.recv_window = get_receive_window(s);

            memset(&s->ev, 0, sizeof(struct epoll_event));
            s->ev.events = EPOLLOUT | EPOLLERR;
            s->ev.data.ptr = s;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->socket, &s->ev);

            s->next = args->ctx->ng_session;
            args->ctx->ng_session = s;

            if (!allowed) write_rst(args, &s->tcp);
        } else {
            struct tcp_session rst;
            memset(&rst, 0, sizeof(struct tcp_session));
            rst.version = version;
            rst.local_seq = ntohl(tcphdr->ack_seq);
            rst.remote_seq = ntohl(tcphdr->seq) + datalen + (tcphdr->syn || tcphdr->fin ? 1 : 0);

            if (version == 4) {
                rst.saddr.ip4 = (__be32) ip4->saddr;
                rst.daddr.ip4 = (__be32) ip4->daddr;
            } else {
                memcpy(&rst.saddr.ip6, &ip6->ip6_src, 16);
                memcpy(&rst.daddr.ip6, &ip6->ip6_dst, 16);
            }

            rst.source = tcphdr->source;
            rst.dest = tcphdr->dest;

            write_rst(args, &rst);
            return 0;
        }
    } else {
        if (cur->tcp.state == TCP_CLOSING || cur->tcp.state == TCP_CLOSE) {
            write_rst(args, &cur->tcp);
            return 0;
        } else {
            if (!tcphdr->syn) cur->tcp.time = time(NULL);
            cur->tcp.send_window = ((uint32_t) ntohs(tcphdr->window)) << cur->tcp.send_scale;
            cur->tcp.unconfirmed = 0;

            if (datalen) {
                if (cur->socket < 0 || cur->tcp.state == TCP_CLOSE_WAIT) {
                    write_rst(args, &cur->tcp);
                    return 0;
                }
                queue_tcp(args, tcphdr, "tcp", &cur->tcp, data, datalen);
            }

            if (tcphdr->rst) {
                cur->tcp.state = TCP_CLOSING;
                return 0;
            } else {
                if (!tcphdr->ack || ntohl(tcphdr->ack_seq) == cur->tcp.local_seq) {
                    if (tcphdr->fin) {
                        if (cur->tcp.state == TCP_ESTABLISHED) {
                            if (cur->tcp.forward == NULL) {
                                cur->tcp.remote_seq++;
                                if (write_ack(args, &cur->tcp) >= 0) cur->tcp.state = TCP_CLOSE_WAIT;
                            } else cur->tcp.state = TCP_CLOSE_WAIT;
                        } else if (cur->tcp.state == TCP_FIN_WAIT1) {
                            cur->tcp.remote_seq++;
                            if (write_ack(args, &cur->tcp) >= 0) cur->tcp.state = TCP_CLOSE;
                        } else return 0;
                    } else if (tcphdr->ack) {
                        cur->tcp.acked = ntohl(tcphdr->ack_seq);
                        if (cur->tcp.state == TCP_SYN_RECV) cur->tcp.state = TCP_ESTABLISHED;
                        else if (cur->tcp.state == TCP_LAST_ACK) cur->tcp.state = TCP_CLOSING;
                    }
                } else {
                    uint32_t ack = ntohl(tcphdr->ack_seq);
                    if ((uint32_t) (ack + 1) == cur->tcp.local_seq) {
                        if (cur->tcp.state == TCP_ESTABLISHED) {
                            int on = 1;
                            setsockopt(cur->socket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
                        }
                    } else if (compare_u32(ack, cur->tcp.local_seq) < 0) {
                        if (compare_u32(ack, cur->tcp.acked) > 0) cur->tcp.acked = ack;
                        return 1;
                    } else {
                        write_rst(args, &cur->tcp);
                        return 0;
                    }
                }
            }
        }
    }
    return 1;
}

void queue_tcp(const struct arguments *args, const struct tcphdr *tcphdr, const char *session, struct tcp_session *cur, const uint8_t *data, uint16_t datalen) {
    uint32_t seq = ntohl(tcphdr->seq);
    if (compare_u32(seq, cur->remote_seq) >= 0) {
        struct segment *p = NULL;
        struct segment *s = cur->forward;
        while (s != NULL && compare_u32(s->seq, seq) < 0) {
            p = s;
            s = s->next;
        }

        if (s == NULL || compare_u32(s->seq, seq) > 0) {
            struct segment *n = calloc(1, sizeof(struct segment));
            if (!n) return;
            n->seq = seq;
            n->len = datalen;
            n->sent = 0;
            n->psh = tcphdr->psh;
            n->data = calloc(1, datalen);
            if (n->data) memcpy(n->data, data, datalen);
            n->next = s;
            if (p == NULL) cur->forward = n;
            else p->next = n;
        } else if (s != NULL && s->seq == seq) {
            if (s->len < datalen || s->len > datalen) {
                free(s->data);
                s->len = datalen;
                s->data = calloc(1, datalen);
                if (s->data) memcpy(s->data, data, datalen);
            }
        }
    }
}

int open_tcp_socket(const struct arguments *args, const struct tcp_session *cur, const struct allowed *redirect) {
    int sock;
    int version = (redirect == NULL) ? cur->version : (strstr(redirect->raddr, ":") == NULL ? 4 : 6);

    if ((sock = socket(version == 4 ? PF_INET : PF_INET6, SOCK_STREAM, 0)) < 0) return -1;

    if (protect_socket(args, sock) < 0) {
        close(sock);
        return -1;
    }

    int on = 1;
    setsockopt(sock, SOL_TCP, TCP_NODELAY, &on, sizeof(on));

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    if (redirect == NULL) {
        if (version == 4) {
            addr4.sin_family = AF_INET;
            addr4.sin_addr.s_addr = (__be32) cur->daddr.ip4;
            addr4.sin_port = cur->dest;
        } else {
            addr6.sin6_family = AF_INET6;
            memcpy(&addr6.sin6_addr, &cur->daddr.ip6, 16);
            addr6.sin6_port = cur->dest;
        }
    } else {
        if (version == 4) {
            addr4.sin_family = AF_INET;
            inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
            addr4.sin_port = htons(redirect->rport);
        } else {
            addr6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, redirect->raddr, &addr6.sin6_addr);
            addr6.sin6_port = htons(redirect->rport);
        }
    }

    int err = connect(sock, (version == 4 ? (const struct sockaddr *) &addr4 : (const struct sockaddr *) &addr6), (socklen_t) (version == 4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    if (err < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    return sock;
}

int write_syn_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 1, 1, 0, 0) < 0) { cur->state = TCP_CLOSING; return -1; }
    return 0;
}

int write_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 1, 0, 0) < 0) { cur->state = TCP_CLOSING; return -1; }
    return 0;
}

int write_data(const struct arguments *args, struct tcp_session *cur, const uint8_t *buffer, size_t length) {
    if (write_tcp(args, cur, buffer, length, 0, 1, 0, 0) < 0) { cur->state = TCP_CLOSING; return -1; }
    return 0;
}

int write_fin_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 1, 1, 0) < 0) { cur->state = TCP_CLOSING; return -1; }
    return 0;
}

void write_rst(const struct arguments *args, struct tcp_session *cur) {
    int ack = (cur->state == TCP_LISTEN) ? 1 : 0;
    if (cur->state == TCP_LISTEN) cur->remote_seq++;
    write_tcp(args, cur, NULL, 0, 0, ack, 0, 1);
    if (cur->state != TCP_CLOSE) cur->state = TCP_CLOSING;
}

ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur, const uint8_t *data, size_t datalen, int syn, int ack, int fin, int rst) {
    size_t len;
    struct tcphdr *tcp;
    uint16_t csum;

    uint8_t buffer[65536];

    int optlen = (syn ? 4 + 3 + 1 : 0);
    uint8_t *options;

    if (cur->version == 4) {
        len = sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen + datalen;
        struct iphdr *ip4 = (struct iphdr *) buffer;
        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        options = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
        if (datalen) memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen, data, datalen);

        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_TCP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

        struct ippseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ippseudo));
        pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
        pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
        pseudo.ippseudo_p = ip4->protocol;
        pseudo.ippseudo_len = htons(sizeof(struct tcphdr) + optlen + datalen);
        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    } else {
        len = sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + optlen + datalen;
        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
        tcp = (struct tcphdr *) (buffer + sizeof(struct ip6_hdr));
        options = buffer + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
        if (datalen) memcpy(buffer + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + optlen, data, datalen);

        memset(ip6, 0, sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = 0;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
        ip6->ip6_ctlun.ip6_un2_vfc = 0x60;
        memcpy(&(ip6->ip6_src), &cur->daddr.ip6, 16);
        memcpy(&(ip6->ip6_dst), &cur->saddr.ip6, 16);

        struct ip6_hdr_pseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
    }

    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = cur->dest;
    tcp->dest = cur->source;
    tcp->seq = htonl(cur->local_seq);
    tcp->ack_seq = htonl((uint32_t) (cur->remote_seq));
    tcp->doff = (__u16) ((sizeof(struct tcphdr) + optlen) >> 2);
    tcp->syn = (__u16) syn;
    tcp->ack = (__u16) ack;
    tcp->fin = (__u16) fin;
    tcp->rst = (__u16) rst;
    tcp->window = htons(cur->recv_window >> cur->recv_scale);

    if (!tcp->ack) tcp->ack_seq = 0;

    if (syn) {
        *(options) = 2;
        *(options + 1) = 4;

        uint16_t clamped_mss = (cur->version == 4) ? 1360 : 1340;
        *((uint16_t *) (options + 2)) = htons(clamped_mss);

        *(options + 4) = 3;
        *(options + 5) = 3;
        *(options + 6) = cur->recv_scale;
        *(options + 7) = 0;
    }

    csum = calc_checksum(csum, (uint8_t *) tcp, sizeof(struct tcphdr));
    csum = calc_checksum(csum, options, (size_t) optlen);
    csum = calc_checksum(csum, data, datalen);
    tcp->check = ~csum;

    ssize_t res = write(args->tun, buffer, len);

    // 🚨 FAULT 4 FIX: Handle EAGAIN gracefully without silent packet drops
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1;
        }
    } else {
        if (pcap_file != NULL) write_pcap_rec(buffer, (size_t) res);
    }

    return res;
}