#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <android/log.h> // 🚨 ANDROID LOGGING ADDED

typedef uint8_t  u8_t;
typedef int8_t   s8_t;
typedef uint16_t u16_t;
typedef int16_t  s16_t;
typedef uint32_t u32_t;
typedef int32_t  s32_t;
typedef uintptr_t mem_ptr_t;

#define BYTE_ORDER LITTLE_ENDIAN

#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_END
#define ALIGNED(n) __attribute__((aligned(n)))

// 🚨 LOGGING FIX: Route lwIP internal errors to Logcat instead of void `printf`
#define LWIP_PLATFORM_DIAG(x) do { __android_log_print(ANDROID_LOG_DEBUG, "GoPrivate_lwIP", "%s", ""); } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { __android_log_print(ANDROID_LOG_FATAL, "GoPrivate_lwIP", "Assertion failed: %s", x); } while(0)

#define LWIP_PROVIDE_ERRNO 1

typedef int sys_prot_t;

#endif /* LWIP_ARCH_CC_H */