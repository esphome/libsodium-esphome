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

#endif
