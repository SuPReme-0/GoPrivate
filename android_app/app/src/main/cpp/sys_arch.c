#include "lwip/sys.h"
#include <time.h>
#include <pthread.h> // 🚨 ADDED FOR THREAD SAFETY

#if NO_SYS

// Global mutex for lwIP state protection
static pthread_mutex_t lwip_mutex = PTHREAD_MUTEX_INITIALIZER;

u32_t sys_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// 🚨 CONCURRENCY FIX: Protect lwIP memory state from JNI race conditions
sys_prot_t sys_arch_protect(void) {
    pthread_mutex_lock(&lwip_mutex);
    return 1;
}

void sys_arch_unprotect(sys_prot_t p) {
    (void)p;  // unused parameter
    pthread_mutex_unlock(&lwip_mutex);
}

#endif /* NO_SYS */