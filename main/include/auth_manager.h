#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include "esp_err.h"
#include "esp32_signer.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Configuration constants
#define MAX_SESSIONS 10
#define MAX_CLIENTS 20
#define NONCE_VALIDITY_SECONDS 60

// Initialize the authentication manager
esp_err_t auth_manager_init(void);

// Set the authentication key (derives from password)
esp_err_t auth_manager_set_auth_key(const char *password);

// Generate a new nonce
void auth_manager_generate_nonce(void);

// Get current nonce
esp_err_t auth_manager_get_nonce(char *nonce_hex, size_t max_len);

// Verify HMAC for authentication
esp_err_t auth_manager_verify_hmac(const char *client_id, const char *nonce_hex,
                                  const char *method, const char *path,
                                  const char *body, const char *hmac_hex);

// Create a new session
esp_err_t auth_manager_create_session(const char *client_id, char *token_hex, size_t max_len);

// Verify a session token
esp_err_t auth_manager_verify_session(const char *token_hex, char *client_id, size_t max_len);

// Rate limiting functions
esp_err_t auth_manager_check_rate_limit(const char *client_id);
void auth_manager_record_failure(const char *client_id);

// Check if authentication is configured
bool auth_manager_is_configured(void);

// Clear all authentication data
esp_err_t auth_manager_clear(void);

#ifdef __cplusplus
}
#endif

#endif // AUTH_MANAGER_H