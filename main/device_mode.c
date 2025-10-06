#include "device_mode.h"
#include "esp32_signer.h"
#include "driver/gpio.h"
#include "esp_log.h"

static const char *TAG = "DEVICE_MODE";
static device_mode_t current_mode = DEVICE_MODE_SIGNING;

esp_err_t device_mode_init(void)
{
    ESP_LOGI(TAG, "Initializing device mode detection...");

    // Configure GPIO pin for provisioning BOOT button detection
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_INPUT,
        .pin_bit_mask = (1ULL << PROVISIONING_PIN_A),
        .pull_down_en = 0,
        .pull_up_en = 1,  // Enable pull-up resistor
    };
    ESP_ERROR_CHECK(gpio_config(&io_conf));

    // Read GPIO pin to determine mode
    int pin_a_level = gpio_get_level(PROVISIONING_PIN_A);

    // If BOOT button is pressed (GPIO 0 low), enter provisioning mode
    if (pin_a_level == 0) {
        current_mode = DEVICE_MODE_PROVISIONING;
        ESP_LOGW(TAG, "BOOT button pressed - entering PROVISIONING MODE");
    } else {
        current_mode = DEVICE_MODE_SIGNING;
        ESP_LOGI(TAG, "BOOT button not pressed - entering SIGNING MODE");
    }

    return ESP_OK;
}

device_mode_t get_device_mode(void)
{
    return current_mode;
}

bool is_provisioning_mode(void)
{
    return current_mode == DEVICE_MODE_PROVISIONING;
}

bool is_signing_mode(void)
{
    return current_mode == DEVICE_MODE_SIGNING;
}