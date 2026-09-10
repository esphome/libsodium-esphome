#ifndef esphome_platform_H
#define esphome_platform_H

/* ESPHome port: one place to recognise the build target. Code that only
   exists for the ESP8266 is guarded by SODIUM_ESPHOME_ESP8266_PATHS, which the
   host test build also turns on (SODIUM_ESPHOME_TEST_ESP8266_PATHS) so the
   same code runs under the known-answer tests; hooks into the ESP8266
   runtime itself, such as yielding, stay behind SODIUM_ESPHOME_ESP8266. */
#if defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)
#define SODIUM_ESPHOME_ESP8266 1
#endif

#if defined(SODIUM_ESPHOME_ESP8266) || defined(SODIUM_ESPHOME_TEST_ESP8266_PATHS)
#define SODIUM_ESPHOME_ESP8266_PATHS 1
#endif

/* Cores with no 32x32->64 multiply, where every int64 limb product is a
   library call: the LX106 (ESP8266) and the Cortex-M0+ (ARMv6-M, RP2040).
   They get the m15 X25519 ladder; the host test build can ask for the same
   arrangement with SODIUM_ESPHOME_TEST_NARROW_MUL. */
#if defined(SODIUM_ESPHOME_ESP8266_PATHS) || defined(__ARM_ARCH_6M__) || \
    defined(SODIUM_ESPHOME_TEST_NARROW_MUL)
#define SODIUM_ESPHOME_NARROW_MUL 1
#endif

#ifdef SODIUM_ESPHOME_ESP8266_PATHS
/* One SHA256 round per loop pass instead of 64 unrolled (patch 14): about
   1.4 KB less flash. A handshake hashes a few dozen short inputs and the
   transport none, so the per block cost does not reach a connect. */
#define SODIUM_ESPHOME_COMPACT_SHA256 1
#include <stdint.h>
/* Byte-wise little endian access for the unaligned paths of the block loops
   (patches 12 and 13); -Os leaves the library's out of line and the loops
   call them dozens of times per block. */
static inline __attribute__((always_inline)) uint32_t
sodium_esphome_load32_le(const unsigned char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline __attribute__((always_inline)) void
sodium_esphome_store32_le(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) v;
    p[1] = (unsigned char) (v >> 8);
    p[2] = (unsigned char) (v >> 16);
    p[3] = (unsigned char) (v >> 24);
}
#endif

#endif
