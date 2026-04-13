/*
    This file is part of NetGuard.
    Purged, Hardened, and Re-Architected for GoPrivate ML Kernel.
*/

#include "netguard.h"
#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "GoPrivate_JNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// --------------------------------------------------------------------------
// 🚨 KOTLIN JNI GLOBALS
// --------------------------------------------------------------------------
JavaVM* global_jvm = NULL;
jobject global_vpn_service_obj = NULL;
jmethodID intercept_method = NULL;
jmethodID protect_method = NULL;
jmethodID threat_method = NULL; 

struct context *global_ctx = NULL;
pthread_t vpn_thread;

// --------------------------------------------------------------------------
// 🚨 LINKER FIX: THE MISSING GLOBALS
// --------------------------------------------------------------------------
int loglevel = ANDROID_LOG_WARN;
FILE *pcap_file = NULL;

void write_pcap_rec(const uint8_t *buffer, size_t len) {
    // Stubbed: Zero-allocation. We don't write PCAPs in production.
}

// --------------------------------------------------------------------------
// 🚨 STATEFUL IPS: THE THREAT NOTIFICATION BRIDGE
// --------------------------------------------------------------------------
void fire_threat_alert(const char* threat_type, const char* source_ip, int port) {
    if (global_jvm == NULL || global_vpn_service_obj == NULL || threat_method == NULL) return;

    JNIEnv *env;
    int attached = 0;
    if ((*global_jvm)->GetEnv(global_jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*global_jvm)->AttachCurrentThread(global_jvm, &env, NULL) != JNI_OK) return;
        attached = 1;
    }

    jstring j_threat_type = (*env)->NewStringUTF(env, threat_type);
    jstring j_source_ip = (*env)->NewStringUTF(env, source_ip);

    (*env)->CallVoidMethod(env, global_vpn_service_obj, threat_method, j_threat_type, j_source_ip, port);

    (*env)->DeleteLocalRef(env, j_threat_type);
    (*env)->DeleteLocalRef(env, j_source_ip);

    if (attached) (*global_jvm)->DetachCurrentThread(global_jvm);
}

// --------------------------------------------------------------------------
// 🚨 THE KOTLIN INTERCEPTOR BRIDGE
// --------------------------------------------------------------------------
// 🚨 UPGRADE: Added src_port to match the Kotlin signature perfectly
int fire_kotlin_interceptor(const char* src_ip, int src_port, const char* dst_ip, int dst_port, int protocol, int packet_size, int header_size, int tcp_flags) {
    if (global_jvm == NULL || global_vpn_service_obj == NULL || intercept_method == NULL) return 1;

    JNIEnv *env;
    int attached = 0;
    if ((*global_jvm)->GetEnv(global_jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*global_jvm)->AttachCurrentThread(global_jvm, &env, NULL) != JNI_OK) return 1;
        attached = 1;
    }

    jstring j_src_ip = (*env)->NewStringUTF(env, src_ip);
    jstring j_dst_ip = (*env)->NewStringUTF(env, dst_ip);

    // 🚨 UPGRADE: Passing src_port into the CallBooleanMethod
    jboolean is_allowed = (*env)->CallBooleanMethod(env, global_vpn_service_obj, intercept_method,
                                                    j_src_ip, src_port, j_dst_ip, dst_port, protocol, packet_size, header_size, tcp_flags);

    (*env)->DeleteLocalRef(env, j_src_ip);
    (*env)->DeleteLocalRef(env, j_dst_ip);

    if (attached) (*global_jvm)->DetachCurrentThread(global_jvm);
    return is_allowed ? 1 : 0;
}

// --------------------------------------------------------------------------
// 🚨 SOCKET PROTECTOR
// --------------------------------------------------------------------------
int protect_socket(const struct arguments *args, int socket) {
    if (global_jvm == NULL || global_vpn_service_obj == NULL || protect_method == NULL) return -1;

    JNIEnv *env;
    int attached = 0;
    if ((*global_jvm)->GetEnv(global_jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*global_jvm)->AttachCurrentThread(global_jvm, &env, NULL) != JNI_OK) return -1;
        attached = 1;
    }

    jboolean isProtected = (*env)->CallBooleanMethod(env, global_vpn_service_obj, protect_method, socket);
    if (attached) (*global_jvm)->DetachCurrentThread(global_jvm);
    return isProtected ? 0 : -1;
}

// --------------------------------------------------------------------------
// 🚨 ENGINE BOOT SEQUENCE (Called from GoPrivateVpnService.kt)
// --------------------------------------------------------------------------
void* vpn_thread_func(void* arg) {
    struct arguments *args = (struct arguments *)arg;
    LOGD("🛡️ Native NAT Engine Online. Listening to TUN...");

    JNIEnv *env;
    int attached = 0;
    if ((*global_jvm)->GetEnv(global_jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*global_jvm)->AttachCurrentThread(global_jvm, &env, NULL) == JNI_OK) attached = 1;
    }

    handle_events(args);

    if (attached) (*global_jvm)->DetachCurrentThread(global_jvm);
    free(args);
    LOGD("🛑 Native NAT Engine Offline.");
    return NULL;
}

JNIEXPORT void JNICALL Java_com_goprivate_app_core_network_GoPrivateVpnService_nativeStartEngine(JNIEnv *env, jobject thiz, jint fd) {
    if (global_ctx != NULL) return;

    (*env)->GetJavaVM(env, &global_jvm);
    global_vpn_service_obj = (*env)->NewGlobalRef(env, thiz);

    jclass vpnClass = (*env)->GetObjectClass(env, global_vpn_service_obj);
    
    // 🚨 UPGRADE: The JNI string now expects (String, Int, String, Int, Int, Int, Int, Int)
    intercept_method = (*env)->GetMethodID(env, vpnClass, "onNativePacketIntercepted", "(Ljava/lang/String;ILjava/lang/String;IIIII)Z");
    protect_method = (*env)->GetMethodID(env, vpnClass, "protectNativeSocket", "(I)Z");
    threat_method = (*env)->GetMethodID(env, vpnClass, "onThreatDetected", "(Ljava/lang/String;Ljava/lang/String;I)V");

    if (!intercept_method || !protect_method || !threat_method) {
        LOGE("❌ Fatal: Kotlin JNI hooks not found! Ensure GoPrivateVpnService has all required methods.");
        return;
    }

    global_ctx = calloc(1, sizeof(struct context));
    pthread_mutex_init(&global_ctx->lock, NULL);
    pipe(global_ctx->pipefds);

    for (int i = 0; i < 2; i++) {
        int flags = fcntl(global_ctx->pipefds[i], F_GETFL, 0);
        fcntl(global_ctx->pipefds[i], F_SETFL, flags | O_NONBLOCK);
    }

    struct arguments *args = calloc(1, sizeof(struct arguments));
    args->env = env;
    args->instance = global_vpn_service_obj;
    args->tun = fd;
    args->fwd53 = 1; // Forward DNS
    args->ctx = global_ctx;

    pthread_create(&vpn_thread, NULL, vpn_thread_func, args);
}

JNIEXPORT void JNICALL Java_com_goprivate_app_core_network_GoPrivateVpnService_nativeStopEngine(JNIEnv *env, jobject thiz) {
    if (global_ctx == NULL) return;
    LOGD("🛑 Shutting down Native Engine...");

    global_ctx->stopping = 1;
    write(global_ctx->pipefds[1], "w", 1);

    pthread_join(vpn_thread, NULL);

    close(global_ctx->pipefds[0]);
    close(global_ctx->pipefds[1]);
    pthread_mutex_destroy(&global_ctx->lock);
    free(global_ctx);
    global_ctx = NULL;

    if (global_vpn_service_obj) {
        (*env)->DeleteGlobalRef(env, global_vpn_service_obj);
        global_vpn_service_obj = NULL;
    }
}

// --------------------------------------------------------------------------
// 🚨 VAPORIZED LEGACY UI STUBS & FIREWALL UNLOCK
// --------------------------------------------------------------------------
jobject create_packet(const struct arguments *args, jint version, jint protocol, const char *flags, const char *source, jint sport, const char *dest, jint dport, const char *data, jint uid, jboolean allowed) { return NULL; }

struct allowed *is_address_allowed(const struct arguments *args, jobject jpacket) {
    static __thread struct allowed dummy_allow = {0};
    return &dummy_allow;
}

void log_packet(const struct arguments *args, jobject jpacket) { }
void account_usage(const struct arguments *args, jint version, jint protocol, const char *daddr, jint dport, jint uid, jlong sent, jlong received) { }
void dns_resolved(const struct arguments *args, const char *qname, const char *aname, const char *resource, int ttl, jint uid) { }
jboolean is_domain_blocked(const struct arguments *args, const char *name) { return 0; }
jint get_uid_q(const struct arguments *args, jint version, jint protocol, const char *source, jint sport, const char *dest, jint dport) { return -1; }
void report_exit(const struct arguments *args, const char *fmt, ...) { }
void report_error(const struct arguments *args, jint error, const char *fmt, ...) { }
int jniCheckException(JNIEnv *env) { return 0; }

// --------------------------------------------------------------------------
// 🚨 HIGH-SPEED MEMORY ALLOCATORS
// --------------------------------------------------------------------------
void ng_add_alloc(void *ptr, const char *tag) { }
void ng_delete_alloc(void *ptr, const char *file, int line) { }
void *ng_malloc(size_t __byte_count, const char *tag) { return malloc(__byte_count); }
void *ng_calloc(size_t __item_count, size_t __item_size, const char *tag) { return calloc(__item_count, __item_size); }
void *ng_realloc(void *__ptr, size_t __byte_count, const char *tag) { return realloc(__ptr, __byte_count); }
void ng_free(void *__ptr, const char *file, int line) { free(__ptr); }