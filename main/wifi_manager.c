#include "wifi_manager.h"
#include "captive_dns.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs.h"
#include "device_mode.h"
#include <string.h>

static const char *TAG = "WIFI_MANAGER";

#define WIFI_SSID_KEY "wifi_ssid"
#define WIFI_PASSWORD_KEY "wifi_password"
#define MAX_RETRY 5

static int s_retry_num = 0;
static bool s_wifi_connected = false;
static EventGroupHandle_t s_wifi_event_group;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry to connect to the AP (attempt %d/%d)", s_retry_num, MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "Failed to connect to WiFi after %d attempts", MAX_RETRY);
        }
        s_wifi_connected = false;
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        s_wifi_connected = true;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

esp_err_t wifi_manager_init(void)
{
    ESP_LOGI(TAG, "Initializing WiFi manager...");

    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    if (is_provisioning_mode()) {
        ESP_LOGI(TAG, "Starting in Access Point mode for provisioning");
        esp_netif_create_default_wifi_ap();

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));

        esp_event_handler_instance_t instance_any_id;
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                            ESP_EVENT_ANY_ID,
                                                            &wifi_event_handler,
                                                            NULL,
                                                            &instance_any_id));

        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

        // Start Access Point for provisioning
        return wifi_start_ap();
    } else {
        ESP_LOGI(TAG, "Starting in Station mode for operation");
        esp_netif_create_default_wifi_sta();

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));

        esp_event_handler_instance_t instance_any_id;
        esp_event_handler_instance_t instance_got_ip;
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                            ESP_EVENT_ANY_ID,
                                                            &wifi_event_handler,
                                                            NULL,
                                                            &instance_any_id));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                            IP_EVENT_STA_GOT_IP,
                                                            &wifi_event_handler,
                                                            NULL,
                                                            &instance_got_ip));

        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

        // Try to load and connect to saved WiFi credentials
        esp_err_t ret = wifi_connect_saved();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Device in signing mode but no WiFi configured!");
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

esp_err_t wifi_save_credentials(const char* ssid, const char* password)
{
    if (!is_provisioning_mode()) {
        ESP_LOGE(TAG, "Cannot save WiFi credentials - device not in provisioning mode");
        return ESP_ERR_INVALID_STATE;
    }

    if (!ssid || !password) {
        ESP_LOGE(TAG, "Invalid SSID or password");
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error opening NVS handle: %s", esp_err_to_name(err));
        return err;
    }

    // Save SSID
    err = nvs_set_str(nvs_handle, WIFI_SSID_KEY, ssid);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error saving SSID: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    // Save password
    err = nvs_set_str(nvs_handle, WIFI_PASSWORD_KEY, password);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error saving password: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error committing WiFi credentials: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "WiFi credentials saved successfully");
    return ESP_OK;
}

esp_err_t wifi_connect_saved(void)
{
    char ssid[32] = {0};
    char password[64] = {0};

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_handle);

    if (err == ESP_OK) {
        size_t ssid_len = sizeof(ssid);
        size_t password_len = sizeof(password);

        err = nvs_get_str(nvs_handle, WIFI_SSID_KEY, ssid, &ssid_len);
        if (err == ESP_OK) {
            err = nvs_get_str(nvs_handle, WIFI_PASSWORD_KEY, password, &password_len);
        }
        nvs_close(nvs_handle);

        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Using WiFi credentials from NVS");
            return wifi_connect(ssid, password);
        }
    }

    ESP_LOGW(TAG, "No saved WiFi credentials in NVS, trying Kconfig defaults");

#ifdef CONFIG_WIFI_SSID
    if (strlen(CONFIG_WIFI_SSID) > 0 && strlen(CONFIG_WIFI_PASSWORD) > 0) {
        ESP_LOGI(TAG, "Using WiFi credentials from Kconfig");
        return wifi_connect(CONFIG_WIFI_SSID, CONFIG_WIFI_PASSWORD);
    }
#endif

    ESP_LOGE(TAG, "No WiFi credentials available");
    return ESP_ERR_NOT_FOUND;
}

esp_err_t wifi_connect(const char* ssid, const char* password)
{
    if (!ssid || !password) {
        ESP_LOGE(TAG, "Invalid SSID or password");
        return ESP_ERR_INVALID_ARG;
    }

    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };

    strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to WiFi SSID: %s", ssid);

    // Wait for connection
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to WiFi successfully");
        return ESP_OK;
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect to WiFi");
        return ESP_FAIL;
    } else {
        ESP_LOGE(TAG, "Unexpected WiFi connection event");
        return ESP_FAIL;
    }
}

esp_err_t wifi_start_ap(void)
{
    // Generate AP SSID with device MAC
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);

    wifi_config_t wifi_config = {
        .ap = {
            .ssid_len = 0,
            .channel = 1,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
            .ssid_hidden = 0,
            .beacon_interval = 100
        },
    };

    snprintf((char*)wifi_config.ap.ssid, sizeof(wifi_config.ap.ssid),
             "ESP32-Signer-%02X%02X", mac[4], mac[5]);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Access Point started: %s", wifi_config.ap.ssid);
    ESP_LOGI(TAG, "Connect to this network and visit https://192.168.4.1");

    // Start captive DNS server
    esp_err_t dns_ret = captive_dns_start();
    if (dns_ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to start captive DNS server: %s", esp_err_to_name(dns_ret));
    }

    return ESP_OK;
}

bool wifi_is_connected(void)
{
    return s_wifi_connected;
}

esp_err_t wifi_get_ip_info(char* ip_str, size_t ip_str_len)
{
    if (!s_wifi_connected) {
        return ESP_ERR_WIFI_NOT_CONNECT;
    }

    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL) {
        return ESP_FAIL;
    }

    esp_netif_ip_info_t ip_info;
    esp_err_t ret = esp_netif_get_ip_info(netif, &ip_info);
    if (ret != ESP_OK) {
        return ret;
    }

    snprintf(ip_str, ip_str_len, IPSTR, IP2STR(&ip_info.ip));
    return ESP_OK;
}