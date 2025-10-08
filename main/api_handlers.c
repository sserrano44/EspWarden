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
#include "esp_timer.h"
#include <string.h>
#include <stdlib.h>

// Trezor-crypto includes for transaction hashing
#include "sha3.h"

static const char *TAG = "API_HANDLERS";

// Rate limiting constants
#define MAX_REQUESTS_PER_MINUTE 10
#define RATE_LIMIT_WINDOW_MS (60 * 1000)

// Rate limiting state
static uint32_t request_count = 0;
static uint64_t window_start_time = 0;
static SemaphoreHandle_t rate_limit_mutex = NULL;

// Helper function declarations
esp_err_t hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t bytes_len);
static void bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex_str);
static esp_err_t get_signing_key(uint8_t private_key[32]);
static esp_err_t get_ethereum_address(char *address_hex, size_t max_len);
static esp_err_t check_rate_limit(void);
static uint32_t get_remaining_requests(void);

esp_err_t api_handle_health(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /health request");

    // Get current nonce from auth manager
    char nonce_hex[NONCE_SIZE * 2 + 1];
    auth_manager_get_nonce(nonce_hex, sizeof(nonce_hex));

    // Get the actual signing address
    char signing_address[43];
    esp_err_t addr_ret = get_ethereum_address(signing_address, sizeof(signing_address));

    cJSON *json = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("OK");
    cJSON *nonce = cJSON_CreateString(nonce_hex);
    cJSON *rate_remaining = cJSON_CreateNumber(get_remaining_requests());

    cJSON_AddItemToObject(json, "status", status);
    cJSON_AddItemToObject(json, "nonce", nonce);
    cJSON_AddItemToObject(json, "rateRemaining", rate_remaining);

    // Add signing address if available
    if (addr_ret == ESP_OK) {
        cJSON *address = cJSON_CreateString(signing_address);
        cJSON_AddItemToObject(json, "signingAddress", address);
    } else {
        cJSON *address = cJSON_CreateString("address_derivation_failed");
        cJSON_AddItemToObject(json, "signingAddress", address);
    }

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
    cJSON *policy_hash = cJSON_CreateString("0x1234567890abcdef1234567890abcdef12345678"); // Placeholder
    cJSON *secure_boot = cJSON_CreateBool(true);
    cJSON *flash_enc = cJSON_CreateBool(true);
    cJSON *mode = cJSON_CreateString(is_provisioning_mode() ? "provisioning" : "signing");

    // Get the actual signing address
    char signing_address[43];
    esp_err_t addr_ret = get_ethereum_address(signing_address, sizeof(signing_address));
    cJSON *address;
    if (addr_ret == ESP_OK) {
        address = cJSON_CreateString(signing_address);
    } else {
        address = cJSON_CreateString("not_configured");
    }

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
        ESP_LOGD(TAG, "Verifying HMAC for client: %s", client_id);

        // Get the current nonce if not provided
        char current_nonce[NONCE_SIZE * 2 + 1];
        if (strlen(nonce) == 0) {
            auth_manager_get_nonce(current_nonce, sizeof(current_nonce));
            nonce = current_nonce;
        }

        // Reconstruct body for HMAC verification (exclude hmac field)
        cJSON *verification_body = cJSON_CreateObject();
        cJSON_AddStringToObject(verification_body, "clientId", client_id);
        if (nonce_json && cJSON_IsString(nonce_json)) {
            cJSON_AddStringToObject(verification_body, "nonce", nonce);
        }
        char *verification_body_str = cJSON_PrintUnformatted(verification_body);
        cJSON_Delete(verification_body);

        // Verify HMAC(nonce || "POST" || "/unlock" || body_without_hmac)
        esp_err_t verify_result = auth_manager_verify_hmac(
            client_id, nonce, "POST", "/unlock", verification_body_str, hmac
        );

        free(verification_body_str);

        if (verify_result != ESP_OK) {
            cJSON_Delete(json);
            return send_error_response(req, 401, "AUTH_FAILED",
                                     "HMAC verification failed", "INVALID_HMAC");
        }
    }

    ESP_LOGD(TAG, "Authentication successful for client: %s", client_id);

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
    cJSON *password = cJSON_GetObjectItem(json, "password");

    if (!cJSON_IsString(ssid) || !cJSON_IsString(password)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing ssid or password fields", NULL);
    }

    esp_err_t ret = wifi_save_credentials(ssid->valuestring, password->valuestring);
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

    cJSON *key = cJSON_GetObjectItem(json, "key");
    if (!cJSON_IsString(key)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing key field", NULL);
    }

    // Set the auth key
    esp_err_t ret = auth_manager_set_auth_key(key->valuestring);
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
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0) {
            return send_error_response(req, 400, "REQUEST_READ_ERROR",
                                     "Failed to read request body", NULL);
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

    cJSON *mode = cJSON_GetObjectItem(json, "mode");
    if (!cJSON_IsString(mode)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing mode field", NULL);
    }

    uint8_t private_key[32];
    esp_err_t ret = ESP_FAIL;

    if (strcmp(mode->valuestring, "generate") == 0) {
        // Generate new private key
        ret = crypto_generate_private_key(private_key);
        if (ret != ESP_OK) {
            cJSON_Delete(json);
            return send_error_response(req, 500, "KEY_GENERATION_FAILED",
                                     "Failed to generate private key", NULL);
        }
        ESP_LOGI(TAG, "Generated new private key");
    } else if (strcmp(mode->valuestring, "import") == 0) {
        // Import existing private key
        cJSON *key_hex = cJSON_GetObjectItem(json, "key");
        if (!cJSON_IsString(key_hex)) {
            cJSON_Delete(json);
            return send_error_response(req, 400, "MISSING_FIELDS",
                                     "Missing key field for import", NULL);
        }

        ret = hex_to_bytes(key_hex->valuestring, private_key, 32);
        if (ret != ESP_OK) {
            cJSON_Delete(json);
            return send_error_response(req, 400, "INVALID_KEY_FORMAT",
                                     "Invalid private key format", NULL);
        }
        ESP_LOGI(TAG, "Imported private key from hex");
    } else {
        cJSON_Delete(json);
        return send_error_response(req, 400, "INVALID_MODE",
                                 "Mode must be 'generate' or 'import'", NULL);
    }

    cJSON_Delete(json);

    // Store the private key
    ret = storage_set_private_key(private_key);
    if (ret != ESP_OK) {
        // Clear private key from memory
        memset(private_key, 0, sizeof(private_key));
        return send_error_response(req, 500, "STORAGE_FAILED",
                                 "Failed to store private key", NULL);
    }

    // Derive public key and Ethereum address
    uint8_t public_key[64];
    uint8_t eth_address[20];

    ret = crypto_get_public_key(private_key, public_key);
    if (ret != ESP_OK) {
        memset(private_key, 0, sizeof(private_key));
        return send_error_response(req, 500, "KEY_DERIVATION_FAILED",
                                 "Failed to derive public key", NULL);
    }

    ret = crypto_get_ethereum_address(public_key, eth_address);
    if (ret != ESP_OK) {
        memset(private_key, 0, sizeof(private_key));
        return send_error_response(req, 500, "ADDRESS_DERIVATION_FAILED",
                                 "Failed to derive Ethereum address", NULL);
    }

    // Format private key as hex string for backup
    char private_key_str[65]; // 64 hex chars + null terminator
    for (int i = 0; i < 32; i++) {
        snprintf(private_key_str + (i * 2), 3, "%02x", private_key[i]);
    }

    // Format Ethereum address as hex string
    char address_str[43]; // "0x" + 40 hex chars + null terminator
    snprintf(address_str, sizeof(address_str), "0x");
    for (int i = 0; i < 20; i++) {
        snprintf(address_str + 2 + (i * 2), 3, "%02x", eth_address[i]);
    }

    // Create response
    cJSON *response = cJSON_CreateObject();
    cJSON *success = cJSON_CreateBool(true);
    cJSON *address = cJSON_CreateString(address_str);
    cJSON *private_key_json = cJSON_CreateString(private_key_str);

    cJSON_AddItemToObject(response, "success", success);
    cJSON_AddItemToObject(response, "address", address);
    cJSON_AddItemToObject(response, "privateKey", private_key_json);

    // Clear private key from memory immediately after creating JSON
    memset(private_key, 0, sizeof(private_key));

    char *response_string = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_string);

    free(response_string);
    cJSON_Delete(response);

    return send_ret;
}

esp_err_t api_handle_key_status(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /key/status request");

    bool has_key = storage_has_private_key();

    cJSON *response = cJSON_CreateObject();
    cJSON *has_key_json = cJSON_CreateBool(has_key);
    cJSON_AddItemToObject(response, "hasKey", has_key_json);

    if (has_key) {
        // Retrieve private key and derive address
        uint8_t private_key[32];
        esp_err_t ret = storage_get_private_key(private_key);

        if (ret == ESP_OK) {
            uint8_t public_key[64];
            uint8_t eth_address[20];

            ret = crypto_get_public_key(private_key, public_key);
            if (ret == ESP_OK) {
                ret = crypto_get_ethereum_address(public_key, eth_address);
                if (ret == ESP_OK) {
                    // Format Ethereum address as hex string
                    char address_str[43]; // "0x" + 40 hex chars + null terminator
                    snprintf(address_str, sizeof(address_str), "0x");
                    for (int i = 0; i < 20; i++) {
                        snprintf(address_str + 2 + (i * 2), 3, "%02x", eth_address[i]);
                    }

                    cJSON *address = cJSON_CreateString(address_str);
                    cJSON_AddItemToObject(response, "address", address);
                } else {
                    cJSON *address = cJSON_CreateNull();
                    cJSON_AddItemToObject(response, "address", address);
                }
            } else {
                cJSON *address = cJSON_CreateNull();
                cJSON_AddItemToObject(response, "address", address);
            }

            // Clear private key from memory
            memset(private_key, 0, sizeof(private_key));
        } else {
            cJSON *address = cJSON_CreateNull();
            cJSON_AddItemToObject(response, "address", address);
        }
    } else {
        cJSON *address = cJSON_CreateNull();
        cJSON_AddItemToObject(response, "address", address);
    }

    char *response_string = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_string);

    free(response_string);
    cJSON_Delete(response);

    return send_ret;
}

esp_err_t api_handle_policy_config(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /policy configuration request");

    // Read request body
    size_t content_len = req->content_len;
    if (content_len == 0 || content_len > 4096) {
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

    // Initialize policy structure
    policy_t policy;
    memset(&policy, 0, sizeof(policy_t));

    // Parse chain IDs whitelist
    cJSON *chain_ids = cJSON_GetObjectItem(json, "chainIds");
    if (chain_ids && cJSON_IsArray(chain_ids)) {
        int chain_count = cJSON_GetArraySize(chain_ids);
        if (chain_count > MAX_CHAINS) {
            cJSON_Delete(json);
            return send_error_response(req, 400, "TOO_MANY_CHAINS",
                                     "Too many chain IDs", NULL);
        }
        for (int i = 0; i < chain_count; i++) {
            cJSON *chain_item = cJSON_GetArrayItem(chain_ids, i);
            if (cJSON_IsNumber(chain_item)) {
                policy.allowed_chains[policy.num_chains++] = (uint32_t)cJSON_GetNumberValue(chain_item);
            }
        }
    }

    // Parse recipient whitelist
    cJSON *recipients = cJSON_GetObjectItem(json, "recipientWhitelist");
    if (recipients && cJSON_IsArray(recipients)) {
        int recipient_count = cJSON_GetArraySize(recipients);
        if (recipient_count > MAX_WHITELISTED_ADDRESSES) {
            cJSON_Delete(json);
            return send_error_response(req, 400, "TOO_MANY_RECIPIENTS",
                                     "Too many recipient addresses", NULL);
        }
        for (int i = 0; i < recipient_count; i++) {
            cJSON *addr_item = cJSON_GetArrayItem(recipients, i);
            if (cJSON_IsString(addr_item)) {
                const char *addr_str = cJSON_GetStringValue(addr_item);
                if (strlen(addr_str) == 42 && strncmp(addr_str, "0x", 2) == 0) {
                    esp_err_t hex_ret = hex_to_bytes(addr_str + 2, policy.recipient_whitelist[policy.num_recipients], 20);
                    if (hex_ret == ESP_OK) {
                        policy.num_recipients++;
                    }
                }
            }
        }
    }

    // Parse ERC-20 token whitelist
    cJSON *erc20_tokens = cJSON_GetObjectItem(json, "erc20Whitelist");
    if (erc20_tokens && cJSON_IsArray(erc20_tokens)) {
        int token_count = cJSON_GetArraySize(erc20_tokens);
        if (token_count > MAX_WHITELISTED_ADDRESSES) {
            cJSON_Delete(json);
            return send_error_response(req, 400, "TOO_MANY_TOKENS",
                                     "Too many ERC-20 token addresses", NULL);
        }
        for (int i = 0; i < token_count; i++) {
            cJSON *addr_item = cJSON_GetArrayItem(erc20_tokens, i);
            if (cJSON_IsString(addr_item)) {
                const char *addr_str = cJSON_GetStringValue(addr_item);
                if (strlen(addr_str) == 42 && strncmp(addr_str, "0x", 2) == 0) {
                    esp_err_t hex_ret = hex_to_bytes(addr_str + 2, policy.erc20_whitelist[policy.num_erc20_tokens], 20);
                    if (hex_ret == ESP_OK) {
                        policy.num_erc20_tokens++;
                    }
                }
            }
        }
    }

    // Parse contract interaction whitelist
    cJSON *contracts = cJSON_GetObjectItem(json, "contractWhitelist");
    if (contracts && cJSON_IsArray(contracts)) {
        int contract_count = cJSON_GetArraySize(contracts);
        if (contract_count > MAX_WHITELISTED_ADDRESSES) {
            cJSON_Delete(json);
            return send_error_response(req, 400, "TOO_MANY_CONTRACTS",
                                     "Too many contract addresses", NULL);
        }
        for (int i = 0; i < contract_count; i++) {
            cJSON *addr_item = cJSON_GetArrayItem(contracts, i);
            if (cJSON_IsString(addr_item)) {
                const char *addr_str = cJSON_GetStringValue(addr_item);
                if (strlen(addr_str) == 42 && strncmp(addr_str, "0x", 2) == 0) {
                    esp_err_t hex_ret = hex_to_bytes(addr_str + 2, policy.contract_whitelist[policy.num_contracts], 20);
                    if (hex_ret == ESP_OK) {
                        policy.num_contracts++;
                    }
                }
            }
        }
    }

    // Save policy to storage
    esp_err_t save_ret = save_policy(&policy);
    if (save_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "STORAGE_ERROR",
                                 "Failed to save policy", NULL);
    }

    // Create response
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "status", "OK");
    cJSON_AddNumberToObject(response, "chainsConfigured", policy.num_chains);
    cJSON_AddNumberToObject(response, "recipientsConfigured", policy.num_recipients);
    cJSON_AddNumberToObject(response, "tokensConfigured", policy.num_erc20_tokens);
    cJSON_AddNumberToObject(response, "contractsConfigured", policy.num_contracts);

    char *response_str = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_str);

    free(response_str);
    cJSON_Delete(response);
    cJSON_Delete(json);

    ESP_LOGI(TAG, "Policy configuration saved successfully");
    return send_ret;
}

esp_err_t api_handle_policy_status(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /policy/status request");

    // Load current policy
    policy_t policy;
    esp_err_t policy_ret = load_policy(&policy);
    bool has_policy = (policy_ret == ESP_OK && storage_has_policy());

    // Create response JSON
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "hasPolicy", has_policy);

    // Add chain IDs array
    cJSON *chain_ids_array = cJSON_CreateArray();
    for (uint8_t i = 0; i < policy.num_chains; i++) {
        cJSON_AddItemToArray(chain_ids_array, cJSON_CreateNumber(policy.allowed_chains[i]));
    }
    cJSON_AddItemToObject(response, "chainIds", chain_ids_array);

    // Add recipient addresses array
    cJSON *recipients_array = cJSON_CreateArray();
    for (uint8_t i = 0; i < policy.num_recipients; i++) {
        char addr_hex[43]; // "0x" + 40 chars + null terminator
        addr_hex[0] = '0';
        addr_hex[1] = 'x';
        bytes_to_hex(policy.recipient_whitelist[i], 20, addr_hex + 2);
        cJSON_AddItemToArray(recipients_array, cJSON_CreateString(addr_hex));
    }
    cJSON_AddItemToObject(response, "recipientWhitelist", recipients_array);

    // Add ERC-20 token addresses array
    cJSON *erc20_array = cJSON_CreateArray();
    for (uint8_t i = 0; i < policy.num_erc20_tokens; i++) {
        char addr_hex[43];
        addr_hex[0] = '0';
        addr_hex[1] = 'x';
        bytes_to_hex(policy.erc20_whitelist[i], 20, addr_hex + 2);
        cJSON_AddItemToArray(erc20_array, cJSON_CreateString(addr_hex));
    }
    cJSON_AddItemToObject(response, "erc20Whitelist", erc20_array);

    // Add contract addresses array
    cJSON *contracts_array = cJSON_CreateArray();
    for (uint8_t i = 0; i < policy.num_contracts; i++) {
        char addr_hex[43];
        addr_hex[0] = '0';
        addr_hex[1] = 'x';
        bytes_to_hex(policy.contract_whitelist[i], 20, addr_hex + 2);
        cJSON_AddItemToArray(contracts_array, cJSON_CreateString(addr_hex));
    }
    cJSON_AddItemToObject(response, "contractWhitelist", contracts_array);

    char *response_str = cJSON_Print(response);
    esp_err_t send_ret = send_json_response(req, 200, response_str);

    free(response_str);
    cJSON_Delete(response);

    ESP_LOGI(TAG, "Policy status sent successfully");
    return send_ret;
}

esp_err_t api_handle_wipe(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /wipe request");

    // TODO: Implement secure wipe of all stored data
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "Wipe functionality not yet implemented", NULL);
}

// Helper function to convert hex string to bytes
esp_err_t hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t bytes_len)
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

// Helper function to get private key from storage
static esp_err_t get_signing_key(uint8_t private_key[32])
{
    // Check if a private key exists in storage
    if (!storage_has_private_key()) {
        ESP_LOGE(TAG, "No private key configured - device must be provisioned first");
        return ESP_ERR_NOT_FOUND;
    }

    // Retrieve the private key from secure storage
    esp_err_t ret = storage_get_private_key(private_key);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve private key from storage: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGD(TAG, "Retrieved private key from secure storage");
    return ESP_OK;
}

// Helper function to get the Ethereum address from the signing key
static esp_err_t get_ethereum_address(char *address_hex, size_t max_len)
{
    if (!address_hex || max_len < 43) { // 42 chars + null terminator
        return ESP_ERR_INVALID_ARG;
    }

    // Get the private key
    uint8_t private_key[32];
    esp_err_t ret = get_signing_key(private_key);
    if (ret != ESP_OK) {
        return ret;
    }

    // Derive public key
    uint8_t public_key[64];
    ret = crypto_get_public_key(private_key, public_key);
    if (ret != ESP_OK) {
        return ret;
    }

    // Derive Ethereum address
    uint8_t address_bytes[20];
    ret = crypto_get_ethereum_address(public_key, address_bytes);
    if (ret != ESP_OK) {
        return ret;
    }

    // Convert to hex string with 0x prefix
    snprintf(address_hex, max_len, "0x");
    for (int i = 0; i < 20; i++) {
        snprintf(address_hex + 2 + (i * 2), max_len - 2 - (i * 2), "%02x", address_bytes[i]);
    }

    return ESP_OK;
}

esp_err_t api_handle_sign_eip1559(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /sign/eip1559 request");

    // Check rate limiting first
    esp_err_t rate_check = check_rate_limit();
    if (rate_check != ESP_OK) {
        return send_error_response(req, 429, "RATE_LIMITED",
                                 "Too many requests, try again later", NULL);
    }

    // Check if device is in signing mode
    if (is_provisioning_mode()) {
        return send_error_response(req, 403, "PROVISIONING_MODE",
                                 "Cannot sign transactions in provisioning mode", NULL);
    }

    // Parse JSON request body with strict size limits
    size_t content_len = req->content_len;
    if (content_len == 0) {
        return send_error_response(req, 400, "INVALID_REQUEST",
                                 "Empty request body", NULL);
    }
    if (content_len > 1024) {  // Stricter limit for production safety
        ESP_LOGW(TAG, "Request too large: %zu bytes", content_len);
        return send_error_response(req, 413, "REQUEST_TOO_LARGE",
                                 "Request body exceeds maximum size", NULL);
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

    // Build transaction structure for policy validation
    eip1559_tx_t tx;
    tx.chain_id = (uint32_t)cJSON_GetNumberValue(chain_id_json);
    strncpy(tx.nonce, cJSON_GetStringValue(nonce_json), sizeof(tx.nonce) - 1);
    strncpy(tx.max_fee_per_gas, cJSON_GetStringValue(max_fee_json), sizeof(tx.max_fee_per_gas) - 1);
    strncpy(tx.max_priority_fee_per_gas, cJSON_GetStringValue(max_priority_json), sizeof(tx.max_priority_fee_per_gas) - 1);
    strncpy(tx.gas_limit, cJSON_GetStringValue(gas_limit_json), sizeof(tx.gas_limit) - 1);
    strncpy(tx.value, cJSON_GetStringValue(value_json), sizeof(tx.value) - 1);

    // Debug: Log received transaction data
    ESP_LOGD(TAG, "Processing EIP-1559 transaction (chainId: %lu)", tx.chain_id);

    // Parse 'to' address
    const char *to_str = cJSON_GetStringValue(to_json);
    if (strlen(to_str) != 42 || strncmp(to_str, "0x", 2) != 0) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "INVALID_ADDRESS",
                                 "Invalid 'to' address format", NULL);
    }
    esp_err_t hex_ret = hex_to_bytes(to_str + 2, tx.to, 20);
    if (hex_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "INVALID_ADDRESS",
                                 "Failed to parse 'to' address", NULL);
    }

    // Parse transaction data
    const char *data_str = cJSON_GetStringValue(data_json);
    if (data_str && strlen(data_str) > 2 && strncmp(data_str, "0x", 2) == 0) {
        size_t data_hex_len = strlen(data_str) - 2;
        tx.data_len = data_hex_len / 2;
        tx.data = malloc(tx.data_len);
        if (!tx.data) {
            cJSON_Delete(json);
            return send_error_response(req, 500, "INTERNAL_ERROR",
                                     "Memory allocation failed", NULL);
        }
        hex_ret = hex_to_bytes(data_str + 2, tx.data, tx.data_len);
        if (hex_ret != ESP_OK) {
            free(tx.data);
            cJSON_Delete(json);
            return send_error_response(req, 400, "INVALID_DATA",
                                     "Failed to parse transaction data", NULL);
        }
    } else {
        tx.data = NULL;
        tx.data_len = 0;
    }

    // Load and validate against policy
    policy_t policy;
    esp_err_t policy_ret = load_policy(&policy);
    if (policy_ret != ESP_OK) {
        if (tx.data) free(tx.data);
        cJSON_Delete(json);
        return send_error_response(req, 500, "POLICY_ERROR",
                                 "Failed to load policy", NULL);
    }

    esp_err_t validation_ret = validate_eip1559_transaction(&tx, &policy);
    if (validation_ret != ESP_OK) {
        if (tx.data) free(tx.data);
        cJSON_Delete(json);
        return send_error_response(req, 403, "POLICY_VIOLATION",
                                 "Transaction violates policy", NULL);
    }

    // Debug: Log parsed 'to' address

    // Create proper EIP-1559 transaction hash
    transaction_hash_t tx_hash;
    esp_err_t hash_ret = crypto_hash_eip1559_transaction(&tx, &tx_hash);
    if (hash_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "HASH_ERROR",
                                 "Failed to create transaction hash", NULL);
    }

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
    if (tx.data) free(tx.data);

    ESP_LOGD(TAG, "EIP-1559 transaction signed successfully");
    return send_ret;
}

esp_err_t api_handle_sign_eip155(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /sign/eip155 request");

    // Check rate limiting first
    esp_err_t rate_check = check_rate_limit();
    if (rate_check != ESP_OK) {
        return send_error_response(req, 429, "RATE_LIMITED",
                                 "Too many requests, try again later", NULL);
    }

    // Check if device is in signing mode
    if (is_provisioning_mode()) {
        return send_error_response(req, 403, "PROVISIONING_MODE",
                                 "Cannot sign transactions in provisioning mode", NULL);
    }

    // Parse JSON request body with strict size limits
    size_t content_len = req->content_len;
    if (content_len == 0) {
        return send_error_response(req, 400, "INVALID_REQUEST",
                                 "Empty request body", NULL);
    }
    if (content_len > 1024) {  // Stricter limit for production safety
        ESP_LOGW(TAG, "Request too large: %zu bytes", content_len);
        return send_error_response(req, 413, "REQUEST_TOO_LARGE",
                                 "Request body exceeds maximum size", NULL);
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

    // Build transaction structure for policy validation
    eip155_tx_t tx;
    tx.chain_id = (uint32_t)cJSON_GetNumberValue(chain_id_json);
    strncpy(tx.nonce, cJSON_GetStringValue(nonce_json), sizeof(tx.nonce) - 1);
    strncpy(tx.gas_price, cJSON_GetStringValue(gas_price_json), sizeof(tx.gas_price) - 1);
    strncpy(tx.gas_limit, cJSON_GetStringValue(gas_limit_json), sizeof(tx.gas_limit) - 1);
    strncpy(tx.value, cJSON_GetStringValue(value_json), sizeof(tx.value) - 1);

    // Parse 'to' address
    const char *to_str = cJSON_GetStringValue(to_json);
    if (strlen(to_str) != 42 || strncmp(to_str, "0x", 2) != 0) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "INVALID_ADDRESS",
                                 "Invalid 'to' address format", NULL);
    }
    esp_err_t hex_ret = hex_to_bytes(to_str + 2, tx.to, 20);
    if (hex_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "INVALID_ADDRESS",
                                 "Failed to parse 'to' address", NULL);
    }

    // Parse transaction data
    const char *data_str = cJSON_GetStringValue(data_json);
    if (data_str && strlen(data_str) > 2 && strncmp(data_str, "0x", 2) == 0) {
        size_t data_hex_len = strlen(data_str) - 2;
        tx.data_len = data_hex_len / 2;
        tx.data = malloc(tx.data_len);
        if (!tx.data) {
            cJSON_Delete(json);
            return send_error_response(req, 500, "INTERNAL_ERROR",
                                     "Memory allocation failed", NULL);
        }
        hex_ret = hex_to_bytes(data_str + 2, tx.data, tx.data_len);
        if (hex_ret != ESP_OK) {
            free(tx.data);
            cJSON_Delete(json);
            return send_error_response(req, 400, "INVALID_DATA",
                                     "Failed to parse transaction data", NULL);
        }
    } else {
        tx.data = NULL;
        tx.data_len = 0;
    }

    // Load and validate against policy
    policy_t policy;
    esp_err_t policy_ret = load_policy(&policy);
    if (policy_ret != ESP_OK) {
        if (tx.data) free(tx.data);
        cJSON_Delete(json);
        return send_error_response(req, 500, "POLICY_ERROR",
                                 "Failed to load policy", NULL);
    }

    esp_err_t validation_ret = validate_eip155_transaction(&tx, &policy);
    if (validation_ret != ESP_OK) {
        if (tx.data) free(tx.data);
        cJSON_Delete(json);
        return send_error_response(req, 403, "POLICY_VIOLATION",
                                 "Transaction violates policy", NULL);
    }

    // Create proper EIP-155 transaction hash
    transaction_hash_t tx_hash;
    esp_err_t hash_ret = crypto_hash_eip155_transaction(&tx, &tx_hash);
    if (hash_ret != ESP_OK) {
        cJSON_Delete(json);
        return send_error_response(req, 500, "HASH_ERROR",
                                 "Failed to create transaction hash", NULL);
    }

    // Get private key
    uint8_t private_key[32];
    esp_err_t key_ret = get_signing_key(private_key);
    if (key_ret != ESP_OK) {
        if (tx.data) free(tx.data);
        cJSON_Delete(json);
        return send_error_response(req, 500, "KEY_ERROR",
                                 "Failed to retrieve signing key", NULL);
    }

    // Sign the transaction
    ecdsa_signature_t signature;
    esp_err_t sign_ret = crypto_sign_transaction(private_key, &tx_hash, &signature);
    if (sign_ret != ESP_OK) {
        if (tx.data) free(tx.data);
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
    if (tx.data) free(tx.data);

    ESP_LOGD(TAG, "EIP-155 transaction signed successfully");
    return send_ret;
}

// Rate limiting implementation
static esp_err_t check_rate_limit(void)
{
    // Initialize mutex if needed
    if (rate_limit_mutex == NULL) {
        rate_limit_mutex = xSemaphoreCreateMutex();
        if (rate_limit_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create rate limit mutex");
            return ESP_ERR_NO_MEM;
        }
    }

    if (xSemaphoreTake(rate_limit_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Rate limit mutex timeout");
        return ESP_ERR_TIMEOUT;
    }

    uint64_t current_time = esp_timer_get_time() / 1000; // Convert to milliseconds

    // Reset window if enough time has passed
    if (current_time - window_start_time > RATE_LIMIT_WINDOW_MS) {
        window_start_time = current_time;
        request_count = 0;
    }

    // Check if rate limit exceeded
    if (request_count >= MAX_REQUESTS_PER_MINUTE) {
        xSemaphoreGive(rate_limit_mutex);
        ESP_LOGW(TAG, "Rate limit exceeded: %lu requests in window", request_count);
        return ESP_ERR_INVALID_STATE;
    }

    // Increment request count
    request_count++;
    xSemaphoreGive(rate_limit_mutex);
    return ESP_OK;
}

static uint32_t get_remaining_requests(void)
{
    if (rate_limit_mutex == NULL) {
        return MAX_REQUESTS_PER_MINUTE;
    }

    if (xSemaphoreTake(rate_limit_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return 0;
    }

    uint64_t current_time = esp_timer_get_time() / 1000;

    // Reset window if enough time has passed
    if (current_time - window_start_time > RATE_LIMIT_WINDOW_MS) {
        xSemaphoreGive(rate_limit_mutex);
        return MAX_REQUESTS_PER_MINUTE;
    }

    uint32_t remaining = (request_count < MAX_REQUESTS_PER_MINUTE) ?
                        (MAX_REQUESTS_PER_MINUTE - request_count) : 0;
    xSemaphoreGive(rate_limit_mutex);
    return remaining;
}