#include "storage_manager.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <string.h>

static const char *TAG = "STORAGE_MANAGER";
static const char *PRIVATE_KEY_NVS_KEY = "private_key";

esp_err_t storage_manager_init(void)
{
    ESP_LOGI(TAG, "Initializing storage manager...");

    // Initialize NVS if not already done
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "Storage manager initialized successfully");
    return ESP_OK;
}

esp_err_t storage_set_private_key(const uint8_t key[32])
{
    if (!key) {
        ESP_LOGE(TAG, "Private key is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error opening NVS handle: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(nvs_handle, PRIVATE_KEY_NVS_KEY, key, 32);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error saving private key: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error committing private key: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Private key saved successfully");
    return ESP_OK;
}

esp_err_t storage_get_private_key(uint8_t key[32])
{
    if (!key) {
        ESP_LOGE(TAG, "Key buffer is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Cannot open NVS handle for reading private key");
        return err;
    }

    size_t required_size = 32;
    err = nvs_get_blob(nvs_handle, PRIVATE_KEY_NVS_KEY, key, &required_size);
    nvs_close(nvs_handle);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Private key not found in storage");
        return err;
    }

    if (required_size != 32) {
        ESP_LOGE(TAG, "Invalid private key size in storage: %zu", required_size);
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGD(TAG, "Private key retrieved from storage");
    return ESP_OK;
}

bool storage_has_private_key(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        return false;
    }

    size_t required_size = 0;
    err = nvs_get_blob(nvs_handle, PRIVATE_KEY_NVS_KEY, NULL, &required_size);
    nvs_close(nvs_handle);

    return (err == ESP_OK && required_size == 32);
}