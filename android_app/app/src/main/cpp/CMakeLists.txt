cmake_minimum_required(VERSION 3.22.1)
project("goprivate_net")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -flto -ffast-math")

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/netguard_core
)

set(NETGUARD_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/dhcp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/dns.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/icmp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/ip.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/netguard.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/session.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/tcp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/tls.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/udp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/netguard_core/util.c"
)

# Compile everything directly into your library
add_library(
    goprivate_net
    SHARED
    ${NETGUARD_SRC}
)

find_library(log-lib log)
target_link_libraries(
    goprivate_net
    ${log-lib}
    android
)