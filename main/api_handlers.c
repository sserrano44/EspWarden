#include "api_handlers.h"
#include "https_server.h"
#include "esp32_signer.h"
#include "device_mode.h"
#include "wifi_manager.h"
#include "cJSON.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "API_HANDLERS";

esp_err_t api_handle_health(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /health request");

    cJSON *json = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("OK");
    cJSON *nonce = cJSON_CreateString("placeholder_nonce_123456789abcdef");
    cJSON *rate_remaining = cJSON_CreateNumber(10);

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

    cJSON *client_id = cJSON_GetObjectItem(json, "clientId");
    cJSON *hmac = cJSON_GetObjectItem(json, "hmac");

    if (!cJSON_IsString(client_id) || !cJSON_IsString(hmac)) {
        cJSON_Delete(json);
        return send_error_response(req, 400, "MISSING_FIELDS",
                                 "Missing clientId or hmac fields", NULL);
    }

    // TODO: Implement actual HMAC verification
    ESP_LOGI(TAG, "Unlock request from client: %s", client_id->valuestring);

    // Return temporary token
    cJSON *response = cJSON_CreateObject();
    cJSON *token = cJSON_CreateString("temp_token_123456789abcdef0123456789abcdef");
    cJSON *ttl = cJSON_CreateNumber(60);

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

    // TODO: Implement auth key derivation and storage
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "Auth configuration not yet implemented", NULL);
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

esp_err_t api_handle_sign_eip1559(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /sign/eip1559 request");

    // TODO: Implement EIP-1559 transaction signing
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "EIP-1559 signing not yet implemented", NULL);
}

esp_err_t api_handle_sign_eip155(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Handling /sign/eip155 request");

    // TODO: Implement EIP-155 transaction signing
    return send_error_response(req, 501, "NOT_IMPLEMENTED",
                             "EIP-155 signing not yet implemented", NULL);
}