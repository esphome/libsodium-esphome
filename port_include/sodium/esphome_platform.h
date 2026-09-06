#ifndef esphome_platform_H
#define esphome_platform_H

/* ESPHome port: one place to recognise the ESP8266 build. Code that only
   exists for that core is guarded by SODIUM_ESPHOME_ESP8266_PATHS, which the
   host test build also turns on (SODIUM_ESPHOME_TEST_ESP8266_PATHS) so the
   same code runs under the known-answer tests; hooks into the ESP8266
   runtime itself, such as yielding, stay behind SODIUM_ESPHOME_ESP8266. */
#if defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)
#define SODIUM_ESPHOME_ESP8266 1
#endif

#if defined(SODIUM_ESPHOME_ESP8266) || defined(SODIUM_ESPHOME_TEST_ESP8266_PATHS)
#define SODIUM_ESPHOME_ESP8266_PATHS 1
#endif

#endif
