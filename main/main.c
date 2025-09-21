#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp32_signer.h"
#include "device_mode.h"
#include "wifi_manager.h"
#include "https_server.h"
#include "auth_manager.h"

static const char *TAG = "ESP32_SIGNER";

#define FIRMWARE_VERSION "v1.0.0-alpha"

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32 Remote Signer starting up...");
    ESP_LOGI(TAG, "Firmware version: %s", FIRMWARE_VERSION);

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize signer components
    ESP_ERROR_CHECK(signer_init());

    // Determine device mode based on GPIO jumper
    device_mode_t mode = get_device_mode();

    if (mode == DEVICE_MODE_PROVISIONING) {
        ESP_LOGW(TAG, "*** PROVISIONING MODE ENABLED ***");
        ESP_LOGW(TAG, "*** DEVICE ACCEPTS CONFIGURATION CHANGES ***");
    } else {
        ESP_LOGI(TAG, "Device in signing mode - read-only operation");
    }

    // Initialize WiFi
    ESP_ERROR_CHECK(wifi_manager_init());

    // Start HTTPS server
    ESP_ERROR_CHECK(https_server_start());

    ESP_LOGI(TAG, "ESP32 Remote Signer ready for operation");

    // Main loop - keep the device running
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

esp_err_t signer_init(void)
{
    ESP_LOGI(TAG, "Initializing ESP32 Remote Signer components...");

    // Initialize device mode detection
    ESP_ERROR_CHECK(device_mode_init());

    // Initialize authentication manager
    ESP_ERROR_CHECK(auth_manager_init());

    // Initialize other components will be added here
    // ESP_ERROR_CHECK(crypto_manager_init());
    // ESP_ERROR_CHECK(storage_manager_init());
    // ESP_ERROR_CHECK(policy_engine_init());
    // ESP_ERROR_CHECK(rate_limiter_init());

    return ESP_OK;
}

const char* get_firmware_version(void)
{
    return FIRMWARE_VERSION;
}