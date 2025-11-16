#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief mDNS device operation modes
 */
typedef enum {
    MDNS_MODE_PROVISIONING = 0,  ///< Device in provisioning/setup mode (AP)
    MDNS_MODE_SIGNING      = 1   ///< Device in signing/operational mode (STA)
} mdns_device_mode_t;

/**
 * @brief Initialize mDNS manager with hostname, mode, and HTTPS port
 *
 * Sets up mDNS advertising with mode-aware instance names and TXT records.
 * Registers Wi-Fi event handlers to start/stop mDNS based on network state.
 *
 * @param hostname Device hostname (will be advertised as hostname.local)
 * @param mode Device operation mode (affects instance name and TXT records)
 * @param https_port HTTPS server port for service advertisement
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t mdns_manager_init(const char *hostname, mdns_device_mode_t mode, uint16_t https_port);

/**
 * @brief Deinitialize mDNS manager and cleanup resources
 *
 * Stops mDNS if running and unregisters all event handlers.
 */
void mdns_manager_deinit(void);

/**
 * @brief Update device mode and optionally HTTPS port
 *
 * Changes the advertised instance name and TXT records to reflect the new mode.
 * If mDNS is currently running, restarts it with new settings.
 *
 * @param mode New device operation mode
 * @param https_port New HTTPS port (0 = keep current port)
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t mdns_manager_set_mode(mdns_device_mode_t mode, uint16_t https_port);

/**
 * @brief Update device hostname
 *
 * Changes the advertised hostname. If mDNS is currently running, restarts it
 * with the new hostname.
 *
 * @param hostname New hostname (must not be NULL or empty)
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if hostname is invalid
 */
esp_err_t mdns_manager_set_hostname(const char *hostname);

/**
 * @brief Update device hostname and persist to storage
 *
 * Changes the advertised hostname, saves it to storage, and restarts mDNS
 * if currently running.
 *
 * @param hostname New hostname (must not be NULL or empty)
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t mdns_manager_update_hostname(const char *hostname);

#ifdef __cplusplus
}
#endif