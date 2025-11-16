#include "mdns_manager.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "mdns.h"

static const char *TAG = "mdns_mgr";

// State variables
static bool s_running = false;
static mdns_device_mode_t s_mode = MDNS_MODE_SIGNING;
static uint16_t s_https_port = 443;
static char s_hostname[64] = "espwarden";

// Event handler instances
static esp_event_handler_instance_t s_handler_got_ip = NULL;
static esp_event_handler_instance_t s_handler_sta_disconnected = NULL;
static esp_event_handler_instance_t s_handler_ap_start = NULL;
static esp_event_handler_instance_t s_handler_ap_stop = NULL;

/**
 * @brief Get MAC address tail for instance naming
 *
 * Extracts the last 3 bytes of the MAC address as uppercase hex string.
 * Falls back to alternative interface if primary interface fails.
 */
static void get_mac_tail(char out[7], wifi_interface_t ifx)
{
    uint8_t mac[6] = {0};

    if (esp_wifi_get_mac(ifx, mac) != ESP_OK) {
        // Fallback to alternative interface
        wifi_interface_t fallback_ifx = (ifx == WIFI_IF_STA) ? WIFI_IF_AP : WIFI_IF_STA;
        if (esp_wifi_get_mac(fallback_ifx, mac) != ESP_OK) {
            ESP_LOGW(TAG, "Failed to get MAC address, using default");
            snprintf(out, 7, "000000");
            return;
        }
    }

    snprintf(out, 7, "%02X%02X%02X", mac[3], mac[4], mac[5]);
}

/**
 * @brief Configure mDNS service announcement
 *
 * Sets up hostname, instance name, and service with TXT records based on current mode.
 */
static esp_err_t configure_mdns_service(void)
{
    esp_err_t ret;
    char mac_tail[7];
    char instance_name[64];

    // Get MAC address tail for instance naming
    wifi_interface_t interface = (s_mode == MDNS_MODE_SIGNING) ? WIFI_IF_STA : WIFI_IF_AP;
    get_mac_tail(mac_tail, interface);

    // Build instance name based on mode
    const char *base_name = (s_mode == MDNS_MODE_PROVISIONING) ? "ESP Warden Setup" : "ESP Warden";
    snprintf(instance_name, sizeof(instance_name), "%s (%s)", base_name, mac_tail);

    // Set hostname and instance name
    ret = mdns_hostname_set(s_hostname);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set hostname: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = mdns_instance_name_set(instance_name);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set instance name: %s", esp_err_to_name(ret));
        return ret;
    }

    // Add HTTPS service
    ret = mdns_service_add(NULL, "_https", "_tcp", s_https_port, NULL, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add HTTPS service: %s", esp_err_to_name(ret));
        return ret;
    }

    // Set service instance name
    ret = mdns_service_instance_name_set("_https", "_tcp", instance_name);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set service instance name: %s", esp_err_to_name(ret));
        return ret;
    }

    // Configure TXT records
    mdns_txt_item_t txt_records[] = {
        {"device", "espwarden"},
        {"mode", (s_mode == MDNS_MODE_PROVISIONING) ? "setup" : "sign"},
        {"https", "1"},
        {"path", "/"}
    };

    ret = mdns_service_txt_set("_https", "_tcp", txt_records,
                               sizeof(txt_records) / sizeof(txt_records[0]));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set TXT records: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "mDNS service configured: %s.local, instance=%s, port=%u, mode=%s",
             s_hostname, instance_name, s_https_port,
             (s_mode == MDNS_MODE_PROVISIONING) ? "provisioning" : "signing");

    return ESP_OK;
}

/**
 * @brief Start mDNS service
 *
 * Initializes mDNS and configures service announcement. If already running,
 * stops and restarts to apply new configuration.
 */
static esp_err_t start_mdns_service(void)
{
    esp_err_t ret;

    // Stop if already running
    if (s_running) {
        ESP_LOGI(TAG, "Restarting mDNS service");
        mdns_free();
        s_running = false;
    }

    ESP_LOGI(TAG, "Starting mDNS service - hostname=%s.local, mode=%s, port=%u",
             s_hostname,
             (s_mode == MDNS_MODE_PROVISIONING) ? "provisioning" : "signing",
             s_https_port);

    // Initialize mDNS
    ret = mdns_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize mDNS: %s", esp_err_to_name(ret));
        return ret;
    }

    // Configure service
    ret = configure_mdns_service();
    if (ret != ESP_OK) {
        mdns_free();
        return ret;
    }

    s_running = true;
    ESP_LOGI(TAG, "mDNS service started successfully");

    return ESP_OK;
}

/**
 * @brief Stop mDNS service
 *
 * Safely stops mDNS service if running.
 */
static void stop_mdns_service(void)
{
    if (!s_running) {
        return;
    }

    ESP_LOGI(TAG, "Stopping mDNS service");
    mdns_free();
    s_running = false;
}

// Event handlers
static void on_got_ip(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (s_mode == MDNS_MODE_SIGNING) {
        ESP_LOGI(TAG, "STA got IP, starting mDNS in signing mode");
        esp_err_t ret = start_mdns_service();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start mDNS service: %s", esp_err_to_name(ret));
        }
    }
}

static void on_sta_disconnected(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (s_mode == MDNS_MODE_SIGNING) {
        ESP_LOGI(TAG, "STA disconnected, stopping mDNS");
        stop_mdns_service();
    }
}

static void on_ap_start(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (s_mode == MDNS_MODE_PROVISIONING) {
        ESP_LOGI(TAG, "AP started, starting mDNS in provisioning mode");
        esp_err_t ret = start_mdns_service();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start mDNS service: %s", esp_err_to_name(ret));
        }
    }
}

static void on_ap_stop(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (s_mode == MDNS_MODE_PROVISIONING) {
        ESP_LOGI(TAG, "AP stopped, stopping mDNS");
        stop_mdns_service();
    }
}

// Public API implementation
esp_err_t mdns_manager_init(const char *hostname, mdns_device_mode_t mode, uint16_t https_port)
{
    esp_err_t ret;

    // Validate parameters
    if (hostname && strlen(hostname) > 0) {
        strlcpy(s_hostname, hostname, sizeof(s_hostname));
    }

    s_mode = mode;

    if (https_port > 0) {
        s_https_port = https_port;
    }

    ESP_LOGI(TAG, "Initializing mDNS manager - hostname=%s, mode=%s, port=%u",
             s_hostname, (mode == MDNS_MODE_PROVISIONING) ? "provisioning" : "signing", s_https_port);

    // Register event handlers
    ret = esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                            &on_got_ip, NULL, &s_handler_got_ip);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register IP event handler: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED,
                                            &on_sta_disconnected, NULL, &s_handler_sta_disconnected);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register STA disconnect handler: %s", esp_err_to_name(ret));
        goto cleanup_got_ip;
    }

    ret = esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_AP_START,
                                            &on_ap_start, NULL, &s_handler_ap_start);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register AP start handler: %s", esp_err_to_name(ret));
        goto cleanup_sta_disc;
    }

    ret = esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_AP_STOP,
                                            &on_ap_stop, NULL, &s_handler_ap_stop);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register AP stop handler: %s", esp_err_to_name(ret));
        goto cleanup_ap_start;
    }

    ESP_LOGI(TAG, "mDNS manager initialized successfully");

    // Check if we already have a network connection and should start mDNS immediately
    esp_netif_ip_info_t ip_info;
    esp_netif_t* sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif && esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK) {
        if (ip_info.ip.addr != 0) {
            ESP_LOGI(TAG, "Network already connected, starting mDNS immediately");
            if (s_mode == MDNS_MODE_SIGNING) {
                start_mdns_service();
            }
        }
    }

    return ESP_OK;

    // Cleanup on error
cleanup_ap_start:
    if (s_handler_ap_start) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_START, s_handler_ap_start);
        s_handler_ap_start = NULL;
    }
cleanup_sta_disc:
    if (s_handler_sta_disconnected) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, s_handler_sta_disconnected);
        s_handler_sta_disconnected = NULL;
    }
cleanup_got_ip:
    if (s_handler_got_ip) {
        esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, s_handler_got_ip);
        s_handler_got_ip = NULL;
    }

    return ret;
}

void mdns_manager_deinit(void)
{
    ESP_LOGI(TAG, "Deinitializing mDNS manager");

    // Stop mDNS service
    stop_mdns_service();

    // Unregister event handlers
    if (s_handler_got_ip) {
        esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, s_handler_got_ip);
        s_handler_got_ip = NULL;
    }

    if (s_handler_sta_disconnected) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, s_handler_sta_disconnected);
        s_handler_sta_disconnected = NULL;
    }

    if (s_handler_ap_start) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_START, s_handler_ap_start);
        s_handler_ap_start = NULL;
    }

    if (s_handler_ap_stop) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_STOP, s_handler_ap_stop);
        s_handler_ap_stop = NULL;
    }

    ESP_LOGI(TAG, "mDNS manager deinitialized");
}

esp_err_t mdns_manager_set_mode(mdns_device_mode_t mode, uint16_t https_port)
{
    ESP_LOGI(TAG, "Setting mode=%s, port=%u",
             (mode == MDNS_MODE_PROVISIONING) ? "provisioning" : "signing",
             https_port > 0 ? https_port : s_https_port);

    s_mode = mode;

    if (https_port > 0) {
        s_https_port = https_port;
    }

    // Restart service if currently running to apply new settings
    if (s_running) {
        return start_mdns_service();
    }

    return ESP_OK;
}

esp_err_t mdns_manager_set_hostname(const char *hostname)
{
    if (!hostname || strlen(hostname) == 0) {
        ESP_LOGE(TAG, "Invalid hostname");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Setting hostname=%s", hostname);
    strlcpy(s_hostname, hostname, sizeof(s_hostname));

    // Restart service if currently running to apply new hostname
    if (s_running) {
        return start_mdns_service();
    }

    return ESP_OK;
}