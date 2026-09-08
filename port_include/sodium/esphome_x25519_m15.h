#ifndef esphome_x25519_m15_H
#define esphome_x25519_m15_H

#include "sodium/esphome_platform.h"

/* ESPHome port: variable-base X25519 ladder built on BearSSL's m15 field
   arithmetic (port/x25519_m15.c). It replaces ref10's ladder on the cores
   without a 32x32->64 multiply that esphome_platform.h recognises (ESP8266,
   Cortex-M0+). Cores with the wide multiply, ESP32 and the RP2350's
   Cortex-M33 included, are faster on ref10 and keep it; there the function
   is compiled but unused. */
#ifdef SODIUM_ESPHOME_NARROW_MUL
#define SODIUM_ESPHOME_X25519_M15 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* q = n * p on Curve25519; n and p are the 32 byte little endian X25519
   scalar and u coordinate. Always returns 0; the caller rejects an all zero
   result, which is what a small order point produces. */
int sodium_esphome_x25519_m15(unsigned char *q, const unsigned char *n,
                              const unsigned char *p);

#ifdef __cplusplus
}
#endif

#endif
