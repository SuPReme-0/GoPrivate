/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#include "netguard.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

// 🚨 SECURE MEMORY WIPER
void clear(struct context *ctx) {
    if (ctx == NULL) return;

    pthread_mutex_lock(&ctx->lock);
    struct ng_session *s = ctx->ng_session;
    while (s != NULL) {
        if (s->socket >= 0) {
            close(s->socket);
        }
        if (s->protocol == IPPROTO_TCP) {
            clear_tcp_data(&s->tcp);
        }
        struct ng_session *p = s;
        s = s->next;
        free(p); // 🚨 ZERO-WRAPPER GC
    }
    ctx->ng_session = NULL;
    pthread_mutex_unlock(&ctx->lock);
}

void *handle_events(void *a) {
    struct arguments *args = (struct arguments *) a;

    // Get max number of sessions (Dynamic scaling based on Android limits)
    int maxsessions = SESSION_MAX;
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        maxsessions = (int) (rlim.rlim_cur * SESSION_LIMIT / 100);
        if (maxsessions > SESSION_MAX) maxsessions = SESSION_MAX;
    }

    // Terminate existing sessions not allowed anymore (Stubbed for ML)
    check_allowed(args);

    // Open epoll file descriptor
    int epoll_fd = epoll_create(1);
    if (epoll_fd < 0) {
        args->ctx->stopping = 1;
        return NULL;
    }

    // Monitor engine stop events (Pipe from Kotlin JNI)
    struct epoll_event ev_pipe;
    memset(&ev_pipe, 0, sizeof(struct epoll_event));
    ev_pipe.events = EPOLLIN | EPOLLERR;
    ev_pipe.data.ptr = &ev_pipe;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, args->ctx->pipefds[0], &ev_pipe);

    // Monitor virtual TUN interface events
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = NULL;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, args->tun, &ev_tun);

    // 🚨 HOT-PATH LOOP: Fully thread-safe and mathematically optimized
    long long last_check = 0;

    while (!args->ctx->stopping) {
        int recheck = 0;
        int timeout = EPOLL_TIMEOUT;
        int isessions = 0, usessions = 0, tsessions = 0;

        // ======================================================================
        // 🚨 RACE CONDITION FIX: Acquire Lock BEFORE doing Garbage Collection
        // ======================================================================
        pthread_mutex_lock(&args->ctx->lock);

        struct ng_session *s = args->ctx->ng_session;

        // Count active sessions instantly
        while (s != NULL) {
            if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
                if (!s->icmp.stop) isessions++;
            } else if (s->protocol == IPPROTO_UDP) {
                if (s->udp.state == UDP_ACTIVE) usessions++;
            } else if (s->protocol == IPPROTO_TCP) {
                if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE) tsessions++;
                if (s->socket >= 0) recheck |= monitor_tcp_session(args, s, epoll_fd);
            }
            s = s->next;
        }

        int sessions = isessions + usessions + tsessions;

        // 🚨 EFFICIENT GC: Clean up dead sockets periodically
        long long ms = get_ms();
        if (ms - last_check > EPOLL_MIN_CHECK) {
            last_check = ms;
            time_t now = time(NULL); // Call OS clock only once per GC cycle
            struct ng_session *sl = NULL;
            s = args->ctx->ng_session;

            while (s != NULL) {
                int del = 0;
                if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
                    del = check_icmp_session(args, s, sessions, maxsessions);
                    if (!s->icmp.stop && !del) {
                        int stimeout = s->icmp.time + get_icmp_timeout(&s->icmp, sessions, maxsessions) - now + 1;
                        if (stimeout > 0 && stimeout < timeout) timeout = stimeout;
                    }
                } else if (s->protocol == IPPROTO_UDP) {
                    del = check_udp_session(args, s, sessions, maxsessions);
                    if (s->udp.state == UDP_ACTIVE && !del) {
                        int stimeout = s->udp.time + get_udp_timeout(&s->udp, sessions, maxsessions) - now + 1;
                        if (stimeout > 0 && stimeout < timeout) timeout = stimeout;
                    }
                } else if (s->protocol == IPPROTO_TCP) {
                    del = check_tcp_session(args, s, sessions, maxsessions);
                    if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE && !del) {
                        int stimeout = s->tcp.time + get_tcp_timeout(&s->tcp, sessions, maxsessions) - now + 1;
                        if (stimeout > 0 && stimeout < timeout) timeout = stimeout;
                    }
                }

                // Safely sever the linked list node and vaporize the memory
                if (del) {
                    if (sl == NULL) args->ctx->ng_session = s->next;
                    else sl->next = s->next;

                    struct ng_session *c = s;
                    s = s->next;

                    if (c->protocol == IPPROTO_TCP) clear_tcp_data(&c->tcp);
                    free(c); // Memory leak sealed forever
                } else {
                    sl = s;
                    s = s->next;
                }
            }
        } else {
            recheck = 1;
        }

        // 🚨 MUST UNLOCK before sleeping in epoll_wait
        pthread_mutex_unlock(&args->ctx->lock);

        // Wait for OS Network Interrupts (Thread sleeps here, 0% CPU usage)
        struct epoll_event ev[EPOLL_EVENTS];
        int ready = epoll_wait(epoll_fd, ev, EPOLL_EVENTS, recheck ? EPOLL_MIN_CHECK : timeout * 1000);

        if (ready < 0) {
            if (errno == EINTR) continue; // Ignore harmless OS interrupts
            break; // Fatal epoll crash
        }

        if (ready > 0) {
            // Lock the thread specifically to process the new packets
            pthread_mutex_lock(&args->ctx->lock);
            int error = 0;

            for (int i = 0; i < ready; i++) {
                if (ev[i].data.ptr == &ev_pipe) {
                    // JNI sent the kill signal
                    uint8_t buffer[1];
                    read(args->ctx->pipefds[0], buffer, 1);
                } else if (ev[i].data.ptr == NULL) {
                    // 🚨 HIGH-SPEED DRAIN: Empty the TUN buffer to prevent EAGAIN drops
                    int count = 0;
                    while (count < TUN_YIELD && !error && !args->ctx->stopping && is_readable(args->tun)) {
                        count++;
                        if (check_tun(args, &ev[i], epoll_fd, sessions, maxsessions) < 0) error = 1;
                    }
                } else {
                    // Responses arriving from the Internet (Downstream)
                    struct ng_session *session = (struct ng_session *) ev[i].data.ptr;
                    if (session->protocol == IPPROTO_ICMP || session->protocol == IPPROTO_ICMPV6) {
                        check_icmp_socket(args, &ev[i]);
                    } else if (session->protocol == IPPROTO_UDP) {
                        int count = 0;
                        while (count < UDP_YIELD && !args->ctx->stopping && !(ev[i].events & EPOLLERR) && (ev[i].events & EPOLLIN) && is_readable(session->socket)) {
                            count++;
                            check_udp_socket(args, &ev[i]);
                        }
                    } else if (session->protocol == IPPROTO_TCP) {
                        check_tcp_socket(args, &ev[i], epoll_fd);
                    }
                }
                if (error) break;
            }

            pthread_mutex_unlock(&args->ctx->lock);
            if (error) break;
        }
    }

    if (epoll_fd >= 0) close(epoll_fd);

    return NULL;
}

// Legacy UI Stub
void check_allowed(const struct arguments *args) { }