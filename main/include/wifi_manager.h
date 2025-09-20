#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t wifi_manager_init(void);
esp_err_t wifi_save_credentials(const char* ssid, const char* password);
esp_err_t wifi_connect_saved(void);
esp_err_t wifi_connect(const char* ssid, const char* password);
bool wifi_is_connected(void);
esp_err_t wifi_get_ip_info(char* ip_str, size_t ip_str_len);

#ifdef __cplusplus
}
#endif

#endif // WIFI_MANAGER_H