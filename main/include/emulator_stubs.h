#ifndef EMULATOR_STUBS_H
#define EMULATOR_STUBS_H

#ifdef CONFIG_EMULATOR_BUILD

#include "esp_err.h"
#include "driver/gpio.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Emulator initialization
void emulator_init(void);
void emulator_print_status(void);

// GPIO simulation
int emulator_gpio_get_level(gpio_num_t gpio_num);

// WiFi simulation
esp_err_t emulator_wifi_connect(void);

// NVS simulation
esp_err_t emulator_nvs_init(void);

// Security feature simulation
bool emulator_secure_boot_enabled(void);
bool emulator_flash_encryption_enabled(void);

// Random number generation
uint32_t emulator_random(void);

// Macro overrides for emulator
#ifdef CONFIG_EMULATOR_BUILD
    #define gpio_get_level(x) emulator_gpio_get_level(x)
    #define esp_random() emulator_random()
#endif

#ifdef __cplusplus
}
#endif

#endif // CONFIG_EMULATOR_BUILD

#endif // EMULATOR_STUBS_H