#include "device_mode.h"
#include "esp32_signer.h"
#include "driver/gpio.h"
#include "esp_log.h"

static const char *TAG = "DEVICE_MODE";
static device_mode_t current_mode = DEVICE_MODE_SIGNING;

esp_err_t device_mode_init(void)
{
    ESP_LOGI(TAG, "Initializing device mode detection...");

    // Configure GPIO pins for provisioning jumper detection
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_INPUT,
        .pin_bit_mask = (1ULL << PROVISIONING_PIN_A) | (1ULL << PROVISIONING_PIN_B),
        .pull_down_en = 0,
        .pull_up_en = 1,  // Enable pull-up resistors
    };
    ESP_ERROR_CHECK(gpio_config(&io_conf));

    // Read GPIO pins to determine mode
    int pin_a_level = gpio_get_level(PROVISIONING_PIN_A);
    int pin_b_level = gpio_get_level(PROVISIONING_PIN_B);

    // If both pins are shorted to ground (low), enter provisioning mode
    if (pin_a_level == 0 && pin_b_level == 0) {
        current_mode = DEVICE_MODE_PROVISIONING;
        ESP_LOGW(TAG, "Provisioning jumper detected - entering PROVISIONING MODE");
    } else {
        current_mode = DEVICE_MODE_SIGNING;
        ESP_LOGI(TAG, "No jumper detected - entering SIGNING MODE");
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