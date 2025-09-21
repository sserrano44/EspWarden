/**
 * ESP32 Remote Signer - Emulator Stubs
 *
 * This file provides stub implementations for hardware-specific functions
 * when running in an emulator environment.
 */

#ifdef CONFIG_EMULATOR_BUILD

#include "esp_log.h"
#include "esp_system.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"

static const char *TAG = "EMULATOR_STUBS";

// Simulated GPIO states (can be controlled via environment variables)
static int simulated_gpio_states[GPIO_NUM_MAX] = {0};

/**
 * Initialize emulator stubs
 */
void emulator_init(void)
{
    ESP_LOGI(TAG, "Initializing emulator environment...");

    // Read GPIO simulation from environment
    const char *provisioning_env = getenv("ESP32_PROVISIONING_MODE");
    if (provisioning_env && strcmp(provisioning_env, "1") == 0) {
        ESP_LOGW(TAG, "EMULATOR: Simulating provisioning mode (GPIO 2 & 4 = LOW)");
        simulated_gpio_states[2] = 0;  // GPIO2 LOW
        simulated_gpio_states[4] = 0;  // GPIO4 LOW
    } else {
        ESP_LOGI(TAG, "EMULATOR: Simulating signing mode (GPIO 2 & 4 = HIGH)");
        simulated_gpio_states[2] = 1;  // GPIO2 HIGH
        simulated_gpio_states[4] = 1;  // GPIO4 HIGH
    }

    // Simulate WiFi network availability
    const char *wifi_sim = getenv("ESP32_WIFI_SIMULATION");
    if (wifi_sim && strcmp(wifi_sim, "1") == 0) {
        ESP_LOGI(TAG, "EMULATOR: WiFi simulation enabled");
    }
}

/**
 * Override GPIO get level for emulation
 */
int emulator_gpio_get_level(gpio_num_t gpio_num)
{
    if (gpio_num >= 0 && gpio_num < GPIO_NUM_MAX) {
        int level = simulated_gpio_states[gpio_num];
        ESP_LOGD(TAG, "EMULATOR: GPIO %d level = %d", gpio_num, level);
        return level;
    }
    return 0;
}

/**
 * Simulate WiFi connection
 */
esp_err_t emulator_wifi_connect(void)
{
    ESP_LOGI(TAG, "EMULATOR: Simulating WiFi connection...");

    // Simulate connection delay
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Always succeed in emulator
    ESP_LOGI(TAG, "EMULATOR: WiFi connected (simulated)");
    ESP_LOGI(TAG, "EMULATOR: IP Address: 192.168.1.100 (simulated)");

    return ESP_OK;
}

/**
 * Simulate NVS operations for emulator
 */
esp_err_t emulator_nvs_init(void)
{
    ESP_LOGI(TAG, "EMULATOR: Initializing simulated NVS...");

    // In emulator, we use regular NVS without encryption
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    return ret;
}

/**
 * Mock secure boot status for emulator
 */
bool emulator_secure_boot_enabled(void)
{
    // Always return false in emulator
    ESP_LOGW(TAG, "EMULATOR: Secure boot disabled (not supported in emulation)");
    return false;
}

/**
 * Mock flash encryption status for emulator
 */
bool emulator_flash_encryption_enabled(void)
{
    // Always return false in emulator
    ESP_LOGW(TAG, "EMULATOR: Flash encryption disabled (not supported in emulation)");
    return false;
}

/**
 * Simulate hardware random number generation
 */
uint32_t emulator_random(void)
{
    // Use software random for emulation
    // In real implementation, this would use hardware RNG
    static bool seeded = false;
    if (!seeded) {
        srand(time(NULL));
        seeded = true;
    }
    return rand();
}

/**
 * Log emulator status
 */
void emulator_print_status(void)
{
    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "       ESP32 REMOTE SIGNER - EMULATOR");
    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "Mode: %s",
        (simulated_gpio_states[2] == 0 && simulated_gpio_states[4] == 0)
        ? "PROVISIONING" : "SIGNING");
    ESP_LOGI(TAG, "GPIO 2: %s", simulated_gpio_states[2] ? "HIGH" : "LOW");
    ESP_LOGI(TAG, "GPIO 4: %s", simulated_gpio_states[4] ? "HIGH" : "LOW");
    ESP_LOGI(TAG, "Secure Boot: DISABLED (emulator)");
    ESP_LOGI(TAG, "Flash Encryption: DISABLED (emulator)");
    ESP_LOGI(TAG, "HTTPS Port: 8443 (forwarded from container)");
    ESP_LOGI(TAG, "===========================================");
}

#endif // CONFIG_EMULATOR_BUILD