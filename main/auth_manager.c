#include "auth_manager.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static const char *TAG = "AUTH_MANAGER";

// Auth manager state
typedef struct {
    uint8_t auth_key[AUTH_KEY_SIZE];
    bool auth_key_set;

    // Nonce management
    uint8_t current_nonce[NONCE_SIZE];
    time_t nonce_timestamp;

    // Session management
    struct {
        uint8_t token[SESSION_TOKEN_SIZE];
        char client_id[64];
        time_t expiry;
        bool valid;
    } sessions[MAX_SESSIONS];

    // Rate limiting
    struct {
        char client_id[64];
        int failed_attempts;
        time_t last_attempt;
    } rate_limit[MAX_CLIENTS];
} auth_manager_state_t;

static auth_manager_state_t auth_state = {0};

// Helper function to generate random bytes
static void generate_random_bytes(uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; i += 4) {
        uint32_t random = esp_random();
        size_t copy_len = (length - i) < 4 ? (length - i) : 4;
        memcpy(buffer + i, &random, copy_len);
    }
}

// Convert bytes to hex string
static void bytes_to_hex(const uint8_t *bytes, size_t length, char *hex_str)
{
    for (size_t i = 0; i < length; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[length * 2] = '\0';
}

// Convert hex string to bytes
static bool hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t expected_len)
{
    size_t hex_len = strlen(hex_str);
    if (hex_len != expected_len * 2) {
        return false;
    }

    for (size_t i = 0; i < expected_len; i++) {
        char byte_str[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
        char *endptr;
        long val = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0' || val < 0 || val > 255) {
            return false;
        }
        bytes[i] = (uint8_t)val;
    }
    return true;
}

esp_err_t auth_manager_init(void)
{
    ESP_LOGI(TAG, "Initializing authentication manager...");

    // Clear auth state
    memset(&auth_state, 0, sizeof(auth_state));

    // Load auth key from NVS if it exists
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("auth", NVS_READONLY, &nvs_handle);
    if (err == ESP_OK) {
        size_t key_size = AUTH_KEY_SIZE;
        err = nvs_get_blob(nvs_handle, "auth_key", auth_state.auth_key, &key_size);
        if (err == ESP_OK && key_size == AUTH_KEY_SIZE) {
            auth_state.auth_key_set = true;
            ESP_LOGI(TAG, "Auth key loaded from NVS");
        } else {
            ESP_LOGW(TAG, "No valid auth key found in NVS");
        }
        nvs_close(nvs_handle);
    } else {
        ESP_LOGW(TAG, "Auth NVS namespace not found");
    }

    // Generate initial nonce
    auth_manager_generate_nonce();

    ESP_LOGI(TAG, "Auth manager initialized");
    return ESP_OK;
}

esp_err_t auth_manager_set_auth_key(const char *hex_key)
{
    if (!hex_key) {
        ESP_LOGE(TAG, "Auth key cannot be null");
        return ESP_ERR_INVALID_ARG;
    }

    size_t key_len = strlen(hex_key);
    if (key_len != 64) {
        ESP_LOGE(TAG, "Auth key must be exactly 64 hex characters (got %d)", key_len);
        return ESP_ERR_INVALID_ARG;
    }

    // Validate that all characters are hex
    for (int i = 0; i < 64; i++) {
        char c = hex_key[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            ESP_LOGE(TAG, "Invalid hex character '%c' at position %d", c, i);
            return ESP_ERR_INVALID_ARG;
        }
    }

    ESP_LOGI(TAG, "Converting hex key to bytes...");

    // Convert hex string to bytes
    for (int i = 0; i < AUTH_KEY_SIZE; i++) {
        char hex_byte[3] = {hex_key[i * 2], hex_key[i * 2 + 1], '\0'};
        auth_state.auth_key[i] = (uint8_t)strtol(hex_byte, NULL, 16);
    }

    auth_state.auth_key_set = true;

    // Save to NVS
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("auth", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for auth storage");
        return err;
    }

    err = nvs_set_blob(nvs_handle, "auth_key", auth_state.auth_key, AUTH_KEY_SIZE);
    if (err == ESP_OK) {
        err = nvs_commit(nvs_handle);
    }

    nvs_close(nvs_handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save auth key to NVS");
        return err;
    }

    ESP_LOGI(TAG, "Auth key successfully stored");
    return ESP_OK;
}

void auth_manager_generate_nonce(void)
{
    generate_random_bytes(auth_state.current_nonce, NONCE_SIZE);
    auth_state.nonce_timestamp = time(NULL);

    char nonce_hex[NONCE_SIZE * 2 + 1];
    bytes_to_hex(auth_state.current_nonce, NONCE_SIZE, nonce_hex);
    ESP_LOGD(TAG, "Generated new nonce: %s", nonce_hex);
}

esp_err_t auth_manager_get_nonce(char *nonce_hex, size_t max_len)
{
    if (!nonce_hex || max_len < (NONCE_SIZE * 2 + 1)) {
        return ESP_ERR_INVALID_ARG;
    }

    // Check if nonce is still valid (60 seconds)
    time_t now = time(NULL);
    if (now - auth_state.nonce_timestamp > NONCE_VALIDITY_SECONDS) {
        auth_manager_generate_nonce();
    }

    bytes_to_hex(auth_state.current_nonce, NONCE_SIZE, nonce_hex);
    return ESP_OK;
}

esp_err_t auth_manager_verify_hmac(const char *client_id, const char *nonce_hex,
                                  const char *method, const char *path,
                                  const char *body, const char *hmac_hex)
{
    if (!auth_state.auth_key_set) {
        ESP_LOGE(TAG, "Auth key not set");
        return ESP_ERR_INVALID_STATE;
    }

    // Check rate limiting
    if (auth_manager_check_rate_limit(client_id) != ESP_OK) {
        ESP_LOGW(TAG, "Rate limit exceeded for client: %s", client_id);
        return ESP_ERR_INVALID_STATE;
    }

    // Convert hex nonce to bytes
    uint8_t nonce[NONCE_SIZE];
    if (!hex_to_bytes(nonce_hex, nonce, NONCE_SIZE)) {
        ESP_LOGE(TAG, "Invalid nonce format");
        return ESP_ERR_INVALID_ARG;
    }

    // Verify nonce matches current nonce
    if (memcmp(nonce, auth_state.current_nonce, NONCE_SIZE) != 0) {
        ESP_LOGE(TAG, "Nonce mismatch");
        auth_manager_record_failure(client_id);
        return ESP_FAIL;
    }

    // Check nonce validity
    time_t now = time(NULL);
    if (now - auth_state.nonce_timestamp > NONCE_VALIDITY_SECONDS) {
        ESP_LOGE(TAG, "Nonce expired");
        auth_manager_record_failure(client_id);
        return ESP_FAIL;
    }

    // Construct message: nonce || method || path || body
    size_t msg_len = strlen(nonce_hex) + strlen(method) + strlen(path) +
                    (body ? strlen(body) : 0) + 1;
    char *message = malloc(msg_len);
    if (!message) {
        ESP_LOGE(TAG, "Failed to allocate memory for HMAC message");
        return ESP_ERR_NO_MEM;
    }

    snprintf(message, msg_len, "%s%s%s%s", nonce_hex, method, path, body ? body : "");

    // Debug: Show what message is being used for HMAC calculation
    ESP_LOGI(TAG, "HMAC message: %s", message);

    // Debug: Show auth key (first 16 bytes for security)
    char auth_key_hex[33];
    bytes_to_hex(auth_state.auth_key, 16, auth_key_hex);
    ESP_LOGI(TAG, "Auth key (first 16 bytes): %s", auth_key_hex);

    // Calculate HMAC-SHA256
    uint8_t calculated_hmac[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
        ESP_LOGE(TAG, "Failed to setup HMAC");
        free(message);
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    if (mbedtls_md_hmac_starts(&ctx, auth_state.auth_key, AUTH_KEY_SIZE) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)message, strlen(message)) != 0 ||
        mbedtls_md_hmac_finish(&ctx, calculated_hmac) != 0) {
        ESP_LOGE(TAG, "Failed to calculate HMAC");
        free(message);
        mbedtls_md_free(&ctx);
        auth_manager_record_failure(client_id);
        return ESP_FAIL;
    }

    mbedtls_md_free(&ctx);
    free(message);

    // Convert calculated HMAC to hex
    char calculated_hex[65];
    bytes_to_hex(calculated_hmac, 32, calculated_hex);

    // Compare HMACs
    if (strcasecmp(calculated_hex, hmac_hex) != 0) {
        ESP_LOGE(TAG, "HMAC verification failed");
        ESP_LOGI(TAG, "Expected: %s", calculated_hex);
        ESP_LOGI(TAG, "Received: %s", hmac_hex);
        auth_manager_record_failure(client_id);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "HMAC verified successfully for client: %s", client_id);

    // Invalidate nonce after successful use
    auth_manager_generate_nonce();

    return ESP_OK;
}

esp_err_t auth_manager_create_session(const char *client_id, char *token_hex, size_t max_len)
{
    if (!client_id || !token_hex || max_len < (SESSION_TOKEN_SIZE * 2 + 1)) {
        return ESP_ERR_INVALID_ARG;
    }

    // Find an available session slot
    int slot = -1;
    time_t now = time(NULL);

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!auth_state.sessions[i].valid || auth_state.sessions[i].expiry < now) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        ESP_LOGE(TAG, "No available session slots");
        return ESP_ERR_NO_MEM;
    }

    // Generate session token
    generate_random_bytes(auth_state.sessions[slot].token, SESSION_TOKEN_SIZE);
    strncpy(auth_state.sessions[slot].client_id, client_id, sizeof(auth_state.sessions[slot].client_id) - 1);
    auth_state.sessions[slot].expiry = now + SESSION_TTL_SECONDS;
    auth_state.sessions[slot].valid = true;

    // Convert to hex
    bytes_to_hex(auth_state.sessions[slot].token, SESSION_TOKEN_SIZE, token_hex);

    ESP_LOGI(TAG, "Session created for client: %s (expires in %d seconds)",
             client_id, SESSION_TTL_SECONDS);

    return ESP_OK;
}

esp_err_t auth_manager_verify_session(const char *token_hex, char *client_id, size_t max_len)
{
    if (!token_hex || !client_id) {
        return ESP_ERR_INVALID_ARG;
    }

    // Convert hex token to bytes
    uint8_t token[SESSION_TOKEN_SIZE];
    if (!hex_to_bytes(token_hex, token, SESSION_TOKEN_SIZE)) {
        ESP_LOGE(TAG, "Invalid token format");
        return ESP_ERR_INVALID_ARG;
    }

    time_t now = time(NULL);

    // Find matching session
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (auth_state.sessions[i].valid &&
            auth_state.sessions[i].expiry > now &&
            memcmp(auth_state.sessions[i].token, token, SESSION_TOKEN_SIZE) == 0) {

            if (client_id && max_len > 0) {
                strncpy(client_id, auth_state.sessions[i].client_id, max_len - 1);
                client_id[max_len - 1] = '\0';
            }

            ESP_LOGD(TAG, "Session valid for client: %s", auth_state.sessions[i].client_id);
            return ESP_OK;
        }
    }

    ESP_LOGE(TAG, "Invalid or expired session token");
    return ESP_FAIL;
}

esp_err_t auth_manager_check_rate_limit(const char *client_id)
{
    if (!client_id) {
        return ESP_ERR_INVALID_ARG;
    }

    time_t now = time(NULL);

    // Find or create client entry
    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(auth_state.rate_limit[i].client_id, client_id) == 0) {
            slot = i;
            break;
        } else if (auth_state.rate_limit[i].client_id[0] == '\0') {
            // Empty slot
            if (slot == -1) {
                slot = i;
            }
        }
    }

    if (slot == -1) {
        ESP_LOGW(TAG, "Rate limit table full");
        return ESP_ERR_NO_MEM;
    }

    // Check if client is rate limited
    if (auth_state.rate_limit[slot].failed_attempts >= MAX_FAILED_AUTH_ATTEMPTS) {
        // Check if cooldown period has passed (60 seconds)
        if (now - auth_state.rate_limit[slot].last_attempt < 60) {
            return ESP_FAIL;
        } else {
            // Reset counter
            auth_state.rate_limit[slot].failed_attempts = 0;
        }
    }

    return ESP_OK;
}

void auth_manager_record_failure(const char *client_id)
{
    if (!client_id) {
        return;
    }

    time_t now = time(NULL);

    // Find or create client entry
    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(auth_state.rate_limit[i].client_id, client_id) == 0) {
            slot = i;
            break;
        } else if (auth_state.rate_limit[i].client_id[0] == '\0') {
            if (slot == -1) {
                slot = i;
                strncpy(auth_state.rate_limit[i].client_id, client_id,
                       sizeof(auth_state.rate_limit[i].client_id) - 1);
            }
        }
    }

    if (slot != -1) {
        auth_state.rate_limit[slot].failed_attempts++;
        auth_state.rate_limit[slot].last_attempt = now;

        ESP_LOGW(TAG, "Failed auth attempt %d/%d for client: %s",
                auth_state.rate_limit[slot].failed_attempts,
                MAX_FAILED_AUTH_ATTEMPTS, client_id);
    }
}

bool auth_manager_is_configured(void)
{
    return auth_state.auth_key_set;
}

esp_err_t auth_manager_clear(void)
{
    ESP_LOGW(TAG, "Clearing all authentication data...");

    // Clear memory
    memset(&auth_state, 0, sizeof(auth_state));

    // Clear NVS
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("auth", NVS_READWRITE, &nvs_handle);
    if (err == ESP_OK) {
        nvs_erase_all(nvs_handle);
        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
    }

    ESP_LOGI(TAG, "Authentication data cleared");
    return ESP_OK;
}