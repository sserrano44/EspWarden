#include "api_handlers.h"
#include "https_server.h"
#include "esp32_signer.h"
#include "device_mode.h"
#include "wifi_manager.h"
#include "auth_manager.h"
#include "crypto_manager.h"
#include "storage_manager.h"
#include "policy_engine.h"
#include "cJSON.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

// Trezor-crypto includes for transaction hashing
#include "sha3.h"

static const char *TAG = "API_HANDLERS";

esp_err_t api_handle_health(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /health request");

    // Get current nonce from auth manager
    char nonce_hex[NONCE_SIZE * 2 + 1];
    auth_manager_get_nonce(nonce_hex, sizeof(nonce_hex));

    cJSON *json = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("OK");
    cJSON *nonce = cJSON_CreateString(nonce_hex);
    cJSON *rate_remaining = cJSON_CreateNumber(10);  // TODO: Get from rate limiter

    cJSON_AddItemToObject(json, "status", status);
    cJSON_AddItemToObject(json, "nonce", nonce);
    cJSON_AddItemToObject(json, "rateRemaining", rate_remaining);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = send_json_response(req, 200, json_string);

    free(json_string);
    cJSON_Delete(json);

    return ret;
}

esp_err_t api_handle_info(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /info request");

    cJSON *json = cJSON_CreateObject();
    cJSON *fw = cJSON_CreateString(get_firmware_version());
    cJSON *address = cJSON_CreateString("0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8"); // Placeholder
    cJSON *policy_hash = cJSON_CreateString("0x1234567890abcdef1234567890abcdef12345678"); // Placeholder
    cJSON *secure_boot = cJSON_CreateBool(true);
    cJSON *flash_enc = cJSON_CreateBool(true);
    cJSON *mode = cJSON_CreateString(is_provisioning_mode() ? "provisioning" : "signing");

    cJSON_AddItemToObject(json, "fw", fw);
    cJSON_AddItemToObject(json, "address", address);
    cJSON_AddItemToObject(json, "policyHash", policy_hash);
    cJSON_AddItemToObject(json, "secureBoot", secure_boot);
    cJSON_AddItemToObject(json, "flashEnc", flash_enc);
    cJSON_AddItemToObject(json, "mode", mode);

    char *json_string = cJSON_Print(json);
    esp_err_t ret = send_json_response(req, 200, json_string);

    free(json_string);
    cJSON_Delete(json);

    return ret;
}

esp_err_t api_handle_unlock(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /unlock request");

    // Read request body
    char buf[512];
    int total_len = req->content_len;
    int cur_len = 0;
    int received = 0;

    if (total_len >= sizeof(buf)) {
        return send_error_response(req, 400, "PAYLOAD_TOO_LARGE",
                                 "Request payload too large", NULL);
    }

    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len - cur_len);
        if (received <= 0) {
            return send_error_response(req, 400, "INVALID_REQUEST",
                                     "Failed to receive request body", NULL);
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    // Parse JSON
    cJSON *json = cJSON_Parse(buf);
    if (json == NULL) {
        return send_error_response(req, 400, "INVALID_JSON",
                                 "Invalid JSON in request body", NULL);
    }

    cJSON *client_id_json = cJSON_GetObjectItem(json, "clientId");
    cJSON *hmac_json = cJSON_GetObjectItem(json, "hmac");
    cJSON *nonce_json = cJSON_GetObjectItem(json, "nonce");

    if (!cJSON_IsString(client_id_json) || !cJSON_IsString(hmac_json)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing clientId or hmac fields", NULL);
    }

    const char *client_id = client_id_json->valuestring;
    const char *hmac = hmac_json->valuestring;
    const char *nonce = nonce_json ? nonce_json->valuestring : "";

    // Check if auth is configured
    if (!auth_manager_is_configured()) {
        ESP_LOGW(TAG, "Authentication not configured - accepting any request");
        // For initial setup, accept any request
    } else {
        // Verify HMAC
        ESP_LOGI(TAG, "Verifying HMAC for client: %s", client_id);

        // Get the current nonce if not provided
        char current_nonce[NONCE_SIZE * 2 + 1];
        if (strlen(nonce) == 0) {
            auth_manager_get_nonce(current_nonce, sizeof(current_nonce));
            nonce = current_nonce;
        }

        // Verify HMAC(nonce || "POST" || "/unlock" || body)
        esp_err_t verify_result = auth_manager_verify_hmac(
            client_id, nonce, "POST", "/unlock", buf, hmac
        );

        if (verify_result != ESP_OK) {
            cJSON_Delete(json);
            return send_error_response(req, 401, "AUTH_FAILED",
                                     "HMAC verification failed", "INVALID_HMAC");
        }
    }

    ESP_LOGI(TAG, "Authentication successful for client: %s", client_id);

    // Create session token
    char token_hex[SESSION_TOKEN_SIZE * 2 + 1];
    esp_err_t err = auth_manager_create_session(client_id, token_hex, sizeof(token_hex));

    if (err != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "SESSION_ERROR",
                                 "Failed to create session", NULL);
    }

    // Return session token
    cJSON *response = cJSON_CreateObject();
    cJSON *token = cJSON_CreateString(token_hex);
    cJSON *ttl = cJSON_CreateNumber(SESSION_TTL_SECONDS);

    cJSON_AddItemToObject(response, "token", token);
    cJSON_AddItemToObject(response, "ttl", ttl);

    char *response_string = cJSON_Print(response);
    esp_err_t ret = send_json_response(req, 200, response_string);

    free(response_string);
    cJSON_Delete(response);
    cJSON_Delete(json);

    return ret;
}

esp_err_t api_handle_wifi_config(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /wifi configuration request");

    // Read request body
    char buf[512];
    int total_len = req->content_len;
    int cur_len = 0;
    int received = 0;

    if (total_len >= sizeof(buf)) {
        return send_error_response(req, 400, "PAYLOAD_TOO_LARGE",
                                 "Request payload too large", NULL);
    }

    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len - cur_len);
        if (received <= 0) {
            return send_error_response(req, 400, "INVALID_REQUEST",
                                     "Failed to receive request body", NULL);
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    // Parse JSON
    cJSON *json = cJSON_Parse(buf);
    if (json == NULL) {
        return send_error_response(req, 400, "INVALID_JSON",
                                 "Invalid JSON in request body", NULL);
    }

    cJSON *ssid = cJSON_GetObjectItem(json, "ssid");
    cJSON *psk = cJSON_GetObjectItem(json, "psk");

    if (!cJSON_IsString(ssid) || !cJSON_IsString(psk)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing ssid or psk fields", NULL);
    }

    esp_err_t ret = wifi_save_credentials(ssid->valuestring, psk->valuestring);
    cJSON_Delete(json);

    if (ret != ESP_OK) {
        return send_error_response(req, 500, "STORAGE_FAILED",
                                 "Failed to save WiFi credentials", NULL);
    }

    cJSON *response = cJSON_CreateObject();
    cJSON *success = cJSON_CreateBool(true);
    cJSON_AddItemToObject(response, "success", success);

    char *response_string = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_string);

    free(response_string);
    cJSON_Delete(response);

    return send_ret;
}

esp_err_t api_handle_auth_config(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /auth configuration request");

    // Read request body
    char buf[256];
    int total_len = req->content_len;
    int cur_len = 0;
    int received = 0;

    if (total_len >= sizeof(buf)) {
        return send_error_response(req, 400, "PAYLOAD_TOO_LARGE",
                                 "Request payload too large", NULL);
    }

    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len - cur_len);
        if (received <= 0) {
            return send_error_response(req, 400, "INVALID_REQUEST",
                                     "Failed to receive request body", NULL);
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    // Parse JSON
    cJSON *json = cJSON_Parse(buf);
    if (json == NULL) {
        return send_error_response(req, 400, "INVALID_JSON",
                                 "Invalid JSON in request body", NULL);
    }

    cJSON *password = cJSON_GetObjectItem(json, "password");
    if (!cJSON_IsString(password)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing password field", NULL);
    }

    // Set the auth key
    esp_err_t ret = auth_manager_set_auth_key(password->valuestring);
    cJSON_Delete(json);

    if (ret != ESP_OK) {
        return send_error_response(req, 500, "AUTH_CONFIG_FAILED",
                                 "Failed to configure authentication", NULL);
    }

    cJSON *response = cJSON_CreateObject();
    cJSON *success = cJSON_CreateBool(true);
    cJSON_AddItemToObject(response, "success", success);

    char *response_string = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_string);

    free(response_string);
    cJSON_Delete(response);

    ESP_LOGI(TAG, "Authentication configured successfully");
    return send_ret;
}

esp_err_t api_handle_key_config(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /key configuration request");

    // TODO: Implement key generation/import and storage
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "Key configuration not yet implemented", NULL);
}

esp_err_t api_handle_policy_config(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /policy configuration request");

    // TODO: Implement policy storage and validation
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "Policy configuration not yet implemented", NULL);
}

esp_err_t api_handle_wipe(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /wipe request");

    // TODO: Implement secure wipe of all stored data
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "Wipe functionality not yet implemented", NULL);
}

// Helper function to convert hex string to bytes
__attribute__((unused)) static esp_err_t hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t bytes_len)
{
    if (!hex_str || !bytes) {
        return ESP_ERR_INVALID_ARG;
    }

    // Remove 0x prefix if present
    if (strncmp(hex_str, "0x", 2) == 0) {
        hex_str += 2;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len != bytes_len * 2) {
        return ESP_ERR_INVALID_SIZE;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = {hex_str[i*2], hex_str[i*2+1], 0};
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    return ESP_OK;
}

// Helper function to convert bytes to hex string
static void bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex_str)
{
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(&hex_str[i*2], "%02x", bytes[i]);
    }
    hex_str[bytes_len * 2] = 0;
}

// Helper function to get private key from storage (placeholder)
static esp_err_t get_signing_key(uint8_t private_key[32])
{
    // TODO: Implement secure key retrieval from NVS
    // For now, generate a deterministic test key
    ESP_LOGW(TAG, "Using deterministic test key - DO NOT USE IN PRODUCTION");

    // Generate a simple test key (in production this would come from secure storage)
    for (int i = 0; i < 32; i++) {
        private_key[i] = i + 1;  // Simple pattern for testing
    }

    return ESP_OK;
}

esp_err_t api_handle_sign_eip1559(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /sign/eip1559 request");

    // Check if device is in signing mode
    if (is_provisioning_mode()) {
        return send_error_response(req, 403, "PROVISIONING_MODE",
                                 "Cannot sign transactions in provisioning mode", NULL);
    }

    // Parse JSON request body
    size_t content_len = req->content_len;
    if (content_len == 0 || content_len > 2048) {
        return send_error_response(req, 400, "INVALID_REQUEST",
                                 "Invalid content length", NULL);
    }

    char *buffer = malloc(content_len + 1);
    if (!buffer) {
        return send_error_response(req, 500, "INTERNAL_ERROR",
                                 "Memory allocation failed", NULL);
    }

    int ret = httpd_req_recv(req, buffer, content_len);
    if (ret <= 0) {
        free(buffer);
        return send_error_response(req, 400, "INVALID_REQUEST",
                                 "Failed to receive request body", NULL);
    }
    buffer[content_len] = 0;

    cJSON *json = cJSON_Parse(buffer);
    free(buffer);

    if (!json) {
        return send_error_response(req, 400, "INVALID_JSON",
                                 "Invalid JSON format", NULL);
    }

    // Extract transaction fields
    cJSON *chain_id_json = cJSON_GetObjectItem(json, "chainId");
    cJSON *nonce_json = cJSON_GetObjectItem(json, "nonce");
    cJSON *max_fee_json = cJSON_GetObjectItem(json, "maxFeePerGas");
    cJSON *max_priority_json = cJSON_GetObjectItem(json, "maxPriorityFeePerGas");
    cJSON *gas_limit_json = cJSON_GetObjectItem(json, "gasLimit");
    cJSON *to_json = cJSON_GetObjectItem(json, "to");
    cJSON *value_json = cJSON_GetObjectItem(json, "value");
    cJSON *data_json = cJSON_GetObjectItem(json, "data");

    if (!chain_id_json || !nonce_json || !max_fee_json || !max_priority_json ||
        !gas_limit_json || !to_json || !value_json || !data_json) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing required transaction fields", NULL);
    }

    uint32_t chain_id = (uint32_t)cJSON_GetNumberValue(chain_id_json);

    // TODO: Create transaction hash for EIP-1559
    // This is a simplified implementation - in production you would need proper RLP encoding
    transaction_hash_t tx_hash;
    tx_hash.chain_id = chain_id;

    // Create a simple hash from the transaction data (this is not correct EIP-1559 encoding)
    char tx_string[1024];
    snprintf(tx_string, sizeof(tx_string),
             "%lu:%s:%s:%s:%s:%s:%s:%s",
             (unsigned long)chain_id,
             cJSON_GetStringValue(nonce_json),
             cJSON_GetStringValue(max_fee_json),
             cJSON_GetStringValue(max_priority_json),
             cJSON_GetStringValue(gas_limit_json),
             cJSON_GetStringValue(to_json),
             cJSON_GetStringValue(value_json),
             cJSON_GetStringValue(data_json));

    keccak_256((uint8_t*)tx_string, strlen(tx_string), tx_hash.hash);

    // Get private key
    uint8_t private_key[32];
    esp_err_t key_ret = get_signing_key(private_key);
    if (key_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "KEY_ERROR",
                                 "Failed to retrieve signing key", NULL);
    }

    // Sign the transaction
    ecdsa_signature_t signature;
    esp_err_t sign_ret = crypto_sign_transaction(private_key, &tx_hash, &signature);
    if (sign_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "SIGNING_ERROR",
                                 "Failed to sign transaction", NULL);
    }

    // Convert signature to hex strings
    char r_hex[65], s_hex[65];
    bytes_to_hex(signature.r, 32, r_hex);
    bytes_to_hex(signature.s, 32, s_hex);

    // Create response JSON
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "r", r_hex);
    cJSON_AddStringToObject(response, "s", s_hex);
    cJSON_AddNumberToObject(response, "v", signature.v);

    char *response_str = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_str);

    free(response_str);
    cJSON_Delete(response);
    cJSON_Delete(json);

    ESP_LOGI(TAG, "EIP-1559 transaction signed successfully");
    return send_ret;
}

esp_err_t api_handle_sign_eip155(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /sign/eip155 request");

    // Check if device is in signing mode
    if (is_provisioning_mode()) {
        return send_error_response(req, 403, "PROVISIONING_MODE",
                                 "Cannot sign transactions in provisioning mode", NULL);
    }

    // Parse JSON request body
    size_t content_len = req->content_len;
    if (content_len == 0 || content_len > 2048) {
        return send_error_response(req, 400, "INVALID_REQUEST",
                                 "Invalid content length", NULL);
    }

    char *buffer = malloc(content_len + 1);
    if (!buffer) {
        return send_error_response(req, 500, "INTERNAL_ERROR",
                                 "Memory allocation failed", NULL);
    }

    int ret = httpd_req_recv(req, buffer, content_len);
    if (ret <= 0) {
        free(buffer);
        return send_error_response(req, 400, "INVALID_REQUEST",
                                 "Failed to receive request body", NULL);
    }
    buffer[content_len] = 0;

    cJSON *json = cJSON_Parse(buffer);
    free(buffer);

    if (!json) {
        return send_error_response(req, 400, "INVALID_JSON",
                                 "Invalid JSON format", NULL);
    }

    // Extract transaction fields
    cJSON *chain_id_json = cJSON_GetObjectItem(json, "chainId");
    cJSON *nonce_json = cJSON_GetObjectItem(json, "nonce");
    cJSON *gas_price_json = cJSON_GetObjectItem(json, "gasPrice");
    cJSON *gas_limit_json = cJSON_GetObjectItem(json, "gasLimit");
    cJSON *to_json = cJSON_GetObjectItem(json, "to");
    cJSON *value_json = cJSON_GetObjectItem(json, "value");
    cJSON *data_json = cJSON_GetObjectItem(json, "data");

    if (!chain_id_json || !nonce_json || !gas_price_json ||
        !gas_limit_json || !to_json || !value_json || !data_json) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing required transaction fields", NULL);
    }

    uint32_t chain_id = (uint32_t)cJSON_GetNumberValue(chain_id_json);

    // TODO: Create transaction hash for EIP-155
    // This is a simplified implementation - in production you would need proper RLP encoding
    transaction_hash_t tx_hash;
    tx_hash.chain_id = chain_id;

    // Create a simple hash from the transaction data (this is not correct EIP-155 encoding)
    char tx_string[1024];
    snprintf(tx_string, sizeof(tx_string),
             "%lu:%s:%s:%s:%s:%s:%s",
             (unsigned long)chain_id,
             cJSON_GetStringValue(nonce_json),
             cJSON_GetStringValue(gas_price_json),
             cJSON_GetStringValue(gas_limit_json),
             cJSON_GetStringValue(to_json),
             cJSON_GetStringValue(value_json),
             cJSON_GetStringValue(data_json));

    keccak_256((uint8_t*)tx_string, strlen(tx_string), tx_hash.hash);

    // Get private key
    uint8_t private_key[32];
    esp_err_t key_ret = get_signing_key(private_key);
    if (key_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "KEY_ERROR",
                                 "Failed to retrieve signing key", NULL);
    }

    // Sign the transaction
    ecdsa_signature_t signature;
    esp_err_t sign_ret = crypto_sign_transaction(private_key, &tx_hash, &signature);
    if (sign_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "SIGNING_ERROR",
                                 "Failed to sign transaction", NULL);
    }

    // Convert signature to hex strings
    char r_hex[65], s_hex[65];
    bytes_to_hex(signature.r, 32, r_hex);
    bytes_to_hex(signature.s, 32, s_hex);

    // Create response JSON
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "r", r_hex);
    cJSON_AddStringToObject(response, "s", s_hex);
    cJSON_AddNumberToObject(response, "v", signature.v);

    char *response_str = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_str);

    free(response_str);
    cJSON_Delete(response);
    cJSON_Delete(json);

    ESP_LOGI(TAG, "EIP-155 transaction signed successfully");
    return send_ret;
}