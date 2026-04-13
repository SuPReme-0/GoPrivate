/*
    This file is part of NetGuard.
    Modified, Hardened, and Optimized for GoPrivate ML Kernel.
*/

#ifndef NETGUARD_H
#define NETGUARD_H

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <setjmp.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <android/log.h>
#include <sys/system_properties.h>

#define TAG "NetGuard.JNI"

// --------------------------------------------------------------------------
// 🚨 GIGABIT ROUTING CONSTANTS (Upgraded for 5G / Modern Hardware)
// --------------------------------------------------------------------------
#define EPOLL_TIMEOUT 3600 // seconds
#define EPOLL_EVENTS 64    // Upgraded from 20 for gigabit batching
#define EPOLL_MIN_CHECK 100 // milliseconds

#define TUN_YIELD 50 // Upgraded from 10 to drain TUN buffer faster

#define ICMP4_MAXMSG (IP_MAXPACKET - 20 - 8)
#define ICMP6_MAXMSG (IPV6_MAXPACKET - 40 - 8)
#define UDP4_MAXMSG (IP_MAXPACKET - 20 - 8)
#define UDP6_MAXMSG (IPV6_MAXPACKET - 40 - 8)

#define ICMP_TIMEOUT 5 // seconds

#define UDP_TIMEOUT_53 15 // seconds
#define UDP_TIMEOUT_ANY 300 // seconds
#define UDP_KEEP_TIMEOUT 60 // seconds
#define UDP_YIELD 50 // Upgraded from 10 for high-speed streaming

#define TCP_INIT_TIMEOUT 20 // seconds
#define TCP_IDLE_TIMEOUT 3600 // seconds
#define TCP_CLOSE_TIMEOUT 20 // seconds
#define TCP_KEEP_TIMEOUT 300 // seconds

#define SESSION_LIMIT 80 // Upgraded from 40% to handle modern app loads
#define SESSION_MAX (2048 * SESSION_LIMIT / 100) // Upgraded base connection limit

#define SEND_BUF_DEFAULT 524288 // Upgraded to 512KB for modern TCP Window Scaling

#define UID_MAX_AGE 30000 // milliseconds

#define SOCKS5_NONE 1
#define SOCKS5_HELLO 2
#define SOCKS5_AUTH 3
#define SOCKS5_CONNECT 4
#define SOCKS5_CONNECTED 5

// --------------------------------------------------------------------------
// 🚨 ENGINE STRUCTURES
// --------------------------------------------------------------------------
struct context {
    pthread_mutex_t lock;
    int pipefds[2];
    int stopping;
    int sdk;
    struct ng_session *ng_session;
};

struct arguments {
    JNIEnv *env;
    jobject instance;
    int tun;
    jboolean fwd53;
    jint rcode;
    struct context *ctx;
};

struct allowed {
    char raddr[INET6_ADDRSTRLEN + 1];
    uint16_t rport;
};

struct segment {
    uint32_t seq;
    uint16_t len;
    uint16_t sent;
    int psh;
    uint8_t *data;
    struct segment *next;
};

struct icmp_session {
    time_t time;
    jint uid;
    int version;
    union { __be32 ip4; struct in6_addr ip6; } saddr;
    union { __be32 ip4; struct in6_addr ip6; } daddr;
    uint16_t id;
    uint8_t stop;
};

#define UDP_ACTIVE 0
#define UDP_FINISHING 1
#define UDP_CLOSED 2
#define UDP_BLOCKED 3

struct udp_session {
    time_t time;
    jint uid;
    int version;
    uint16_t mss;
    uint64_t sent;
    uint64_t received;
    union { __be32 ip4; struct in6_addr ip6; } saddr;
    __be16 source;
    union { __be32 ip4; struct in6_addr ip6; } daddr;
    __be16 dest;
    uint8_t state;
};

struct tcp_session {
    jint uid;
    time_t time;
    int version;
    uint16_t mss;
    uint8_t recv_scale;
    uint8_t send_scale;
    uint32_t recv_window;
    uint32_t send_window;
    uint16_t unconfirmed;
    uint32_t remote_seq;
    uint32_t local_seq;
    uint32_t remote_start;
    uint32_t local_start;
    uint32_t acked;
    long long last_keep_alive;
    uint64_t sent;
    uint64_t received;
    union { __be32 ip4; struct in6_addr ip6; } saddr;
    __be16 source;
    union { __be32 ip4; struct in6_addr ip6; } daddr;
    __be16 dest;
    uint8_t state;
    uint8_t socks5;
    struct segment *forward;
};

struct ng_session {
    uint8_t protocol;
    union {
        struct icmp_session icmp;
        struct udp_session udp;
        struct tcp_session tcp;
    };
    jint socket;
    struct epoll_event ev;
    struct ng_session *next;
};

struct uid_cache_entry {
    uint8_t version;
    uint8_t protocol;
    uint8_t saddr[16];
    uint16_t sport;
    uint8_t daddr[16];
    uint16_t dport;
    jint uid;
    long time;
};

struct ip6_hdr_pseudo {
    struct in6_addr ip6ph_src;
    struct in6_addr ip6ph_dst;
    u_int32_t ip6ph_len;
    u_int8_t ip6ph_zero[3];
    u_int8_t ip6ph_nxt;
} __attribute__((packed));

// PCAP
typedef uint16_t guint16_t;
typedef uint32_t guint32_t;
typedef int32_t gint32_t;

typedef struct pcap_hdr_s {
    guint32_t magic_number;
    guint16_t version_major;
    guint16_t version_minor;
    gint32_t thiszone;
    guint32_t sigfigs;
    guint32_t snaplen;
    guint32_t network;
} __attribute__((packed)) pcap_hdr_s;

typedef struct pcaprec_hdr_s {
    guint32_t ts_sec;
    guint32_t ts_usec;
    guint32_t incl_len;
    guint32_t orig_len;
} __attribute__((packed)) pcaprec_hdr_s;

#define LINKTYPE_RAW 101

// TLS
#define TLS_SNI_LENGTH 255
#define TLS_HANDSHAKE_RECORD 22
#define TLS_MESSAGE_CLIENTHELLO 1
#define TLS_EXTENSION_TYPE_SERVER_NAME 0

int get_sni(const uint8_t *data, const uint16_t datalen, char *server_name);

// DNS
#define DNS_QCLASS_IN 1
#define DNS_QTYPE_A 1
#define DNS_QTYPE_AAAA 28
#define DNS_SVCB 64
#define DNS_HTTPS 65
#define DNS_QNAME_MAX 255
#define DNS_TTL (10 * 60)

struct dns_header {
    uint16_t id;
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd :1; uint16_t tc :1; uint16_t aa :1; uint16_t opcode :4; uint16_t qr :1;
    uint16_t rcode :4; uint16_t cd :1; uint16_t ad :1; uint16_t z :1; uint16_t ra :1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t qr :1; uint16_t opcode :4; uint16_t aa :1; uint16_t tc :1; uint16_t rd :1;
    uint16_t ra :1; uint16_t z :1; uint16_t ad :1; uint16_t cd :1; uint16_t rcode :4;
# else
# error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t q_count; uint16_t ans_count; uint16_t auth_count; uint16_t add_count;
} __attribute__((packed));

typedef struct dns_rr {
    __be16 qname_ptr; __be16 qtype; __be16 qclass; __be32 ttl; __be16 rdlength;
} __attribute__((packed)) dns_rr;

// DHCP
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

typedef struct dhcp_packet {
    uint8_t opcode; uint8_t htype; uint8_t hlen; uint8_t hops; uint32_t xid;
    uint16_t secs; uint16_t flags; uint32_t ciaddr; uint32_t yiaddr; uint32_t siaddr;
    uint32_t giaddr; uint8_t chaddr[16]; uint8_t sname[64]; uint8_t file[128]; uint32_t option_format;
} __attribute__((packed)) dhcp_packet;

// --------------------------------------------------------------------------
// 🚨 GOPRIVATE ENGINE PROTOTYPES
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
// 🚨 KOTLIN INTERCEPTOR BRIDGE DECLARATION
// --------------------------------------------------------------------------
int fire_kotlin_interceptor(const char* src_ip, int src_port, const char* dst_ip, int dst_port, int protocol, int packet_size, int header_size, int tcp_flags);
void fire_threat_alert(const char* threat_type, const char* source_ip, int port);

void *handle_events(void *a);
void report_exit(const struct arguments *args, const char *fmt, ...);
void report_error(const struct arguments *args, jint error, const char *fmt, ...);
void check_allowed(const struct arguments *args);
void clear(struct context *ctx);

int check_icmp_session(const struct arguments *args, struct ng_session *s, int sessions, int maxsessions);
int check_udp_session(const struct arguments *args, struct ng_session *s, int sessions, int maxsessions);
int check_tcp_session(const struct arguments *args, struct ng_session *s, int sessions, int maxsessions);
int monitor_tcp_session(const struct arguments *args, struct ng_session *s, int epoll_fd);

int get_icmp_timeout(const struct icmp_session *u, int sessions, int maxsessions);
int get_udp_timeout(const struct udp_session *u, int sessions, int maxsessions);
int get_tcp_timeout(const struct tcp_session *t, int sessions, int maxsessions);

uint16_t get_mtu();
uint16_t get_default_mss(int version);
int check_tun(const struct arguments *args, const struct epoll_event *ev, const int epoll_fd, int sessions, int maxsessions);
void check_icmp_socket(const struct arguments *args, const struct epoll_event *ev);
void check_udp_socket(const struct arguments *args, const struct epoll_event *ev);

int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname);
void parse_dns_response(const struct arguments *args, const struct ng_session *session, const uint8_t *data, size_t *datalen);

uint32_t get_send_window(const struct tcp_session *cur);
uint32_t get_receive_buffer(const struct ng_session *cur);
uint32_t get_receive_window(const struct ng_session *cur);
void check_tcp_socket(const struct arguments *args, const struct epoll_event *ev, const int epoll_fd);

int is_lower_layer(int protocol);
int is_upper_layer(int protocol);
void handle_ip(const struct arguments *args, const uint8_t *buffer, size_t length, const int epoll_fd, int sessions, int maxsessions);

jboolean handle_icmp(const struct arguments *args, const uint8_t *pkt, size_t length, const uint8_t *payload, int uid, const int epoll_fd);
int has_udp_session(const struct arguments *args, const uint8_t *pkt, const uint8_t *payload);
void block_udp(const struct arguments *args, const uint8_t *pkt, size_t length, const uint8_t *payload, int uid);
jboolean handle_udp(const struct arguments *args, const uint8_t *pkt, size_t length, const uint8_t *payload, int uid, struct allowed *redirect, const int epoll_fd);

int check_dhcp(const struct arguments *args, const struct udp_session *u, const uint8_t *data, const size_t datalen);
void clear_tcp_data(struct tcp_session *cur);
jboolean handle_tcp(const struct arguments *args, const uint8_t *pkt, size_t length, const uint8_t *payload, int uid, int allowed, struct allowed *redirect, const int epoll_fd);
void queue_tcp(const struct arguments *args, const struct tcphdr *tcphdr, const char *session, struct tcp_session *cur, const uint8_t *data, uint16_t datalen);

int open_icmp_socket(const struct arguments *args, const struct icmp_session *cur);
int open_udp_socket(const struct arguments *args, const struct udp_session *cur, const struct allowed *redirect);
int open_tcp_socket(const struct arguments *args, const struct tcp_session *cur, const struct allowed *redirect);

int32_t get_local_port(const int sock);
int write_syn_ack(const struct arguments *args, struct tcp_session *cur);
int write_ack(const struct arguments *args, struct tcp_session *cur);
int write_data(const struct arguments *args, struct tcp_session *cur, const uint8_t *buffer, size_t length);
int write_fin_ack(const struct arguments *args, struct tcp_session *cur);
void write_rst(const struct arguments *args, struct tcp_session *cur);
void write_rst_ack(const struct arguments *args, struct tcp_session *cur);

ssize_t write_icmp(const struct arguments *args, const struct icmp_session *cur, uint8_t *data, size_t datalen);
ssize_t write_udp(const struct arguments *args, const struct udp_session *cur, uint8_t *data, size_t datalen);
ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur, const uint8_t *data, size_t datalen, int syn, int ack, int fin, int rst);

uint8_t char2nible(const char c);
void hex2bytes(const char *hex, uint8_t *buffer);

jint get_uid(const int version, const int protocol, const void *saddr, const uint16_t sport, const void *daddr, const uint16_t dport);
jint get_uid_sub(const int version, const int protocol, const void *saddr, const uint16_t sport, const void *daddr, const uint16_t dport, const char *source, const char *dest, long now);
int protect_socket(const struct arguments *args, int socket);
uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length);

int jniCheckException(JNIEnv *env);
int sdk_int(JNIEnv *env);
void log_android(int prio, const char *fmt, ...);
void log_packet(const struct arguments *args, jobject jpacket);
void dns_resolved(const struct arguments *args, const char *qname, const char *aname, const char *resource, int ttl, jint uid);
jboolean is_domain_blocked(const struct arguments *args, const char *name);
jint get_uid_q(const struct arguments *args, jint version, jint protocol, const char *source, jint sport, const char *dest, jint dport);
struct allowed *is_address_allowed(const struct arguments *args, jobject objPacket);
jobject create_packet(const struct arguments *args, jint version, jint protocol, const char *flags, const char *source, jint sport, const char *dest, jint dport, const char *data, jint uid, jboolean allowed);
void account_usage(const struct arguments *args, jint version, jint protocol, const char *daddr, jint dport, jint uid, jlong sent, jlong received);

void write_pcap_hdr();
void write_pcap_rec(const uint8_t *buffer, size_t len);

int compare_u32(uint32_t seq1, uint32_t seq2);
const char *strstate(const int state);
char *hex(const u_int8_t *data, const size_t len);
int is_readable(int fd);
int is_writable(int fd);
long long get_ms();

void ng_add_alloc(void *ptr, const char *tag);
void ng_delete_alloc(void *ptr, const char *file, int line);
void *ng_malloc(size_t __byte_count, const char *tag);
void *ng_calloc(size_t __item_count, size_t __item_size, const char *tag);
void *ng_realloc(void *__ptr, size_t __byte_count, const char *tag);
void ng_free(void *__ptr, const char *file, int line);

#endif // NETGUARD_H