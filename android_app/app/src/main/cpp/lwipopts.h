#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                      1

// 🚨 MEMORY FIX: Expanded to 4MB for high-speed Android networking
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    (4 * 1024 * 1024)

// 🚨 CONCURRENCY FIX: Allow 1000+ simultaneous connections (Spotify, Chrome, etc.)
#define MEMP_NUM_PBUF               2048
#define MEMP_NUM_TCP_PCB            1024
#define MEMP_NUM_TCP_PCB_LISTEN     64
#define MEMP_NUM_TCP_SEG            2048
#define MEMP_NUM_UDP_PCB            512

#define PBUF_POOL_SIZE              2048
#define PBUF_POOL_BUFSIZE           2048

// 🚨 BANDWIDTH FIX: Max out TCP Windows for gigabit speeds
#define TCP_WND                     65535
#define TCP_MSS                     1460
#define TCP_SND_BUF                 (8 * TCP_MSS)
#define TCP_SND_QUEUELEN            (4 * TCP_SND_BUF/TCP_MSS)

// Features
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_SNMP                   0
#define LWIP_DNS                    0
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define LWIP_NETIF_API              0

// IP forwarding
#define IP_FORWARD                  1
#define IP_REASSEMBLY               0 // Drop fragmented packets (prevents buffer bloat)
#define IP_FRAG                     0

// Debug
#define LWIP_DEBUG                  0
#define LWIP_STATS                  0 // Disable stats gathering to save CPU

#endif