#include "https_server.h"
#include "provisioning_page.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "cJSON.h"
#include "device_mode.h"
#include "wifi_manager.h"
#include "api_handlers.h"
#include <string.h>

static const char *TAG = "HTTPS_SERVER";
static httpd_handle_t server = NULL;

// Self-signed certificate for HTTPS
extern const uint8_t server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const uint8_t server_cert_pem_end[]   asm("_binary_server_cert_pem_end");
extern const uint8_t server_key_pem_start[]  asm("_binary_server_key_pem_start");
extern const uint8_t server_key_pem_end[]    asm("_binary_server_key_pem_end");

// Helper function to send JSON response
esp_err_t send_json_response(httpd_req_t *req, int status_code, const char *json_data)
{
    httpd_resp_set_status(req, status_code == 200 ? HTTPD_200 :
                              status_code == 400 ? HTTPD_400 :
                              status_code == 401 ? "401 Unauthorized" :
                              status_code == 403 ? "403 Forbidden" :
                              status_code == 429 ? "429 Too Many Requests" :
                              HTTPD_500);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type, Authorization");

    return httpd_resp_send(req, json_data, strlen(json_data));
}

// Error response helper
esp_err_t send_error_response(httpd_req_t *req, int status_code, const char *error_code, const char *message, const char *reason)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *code_json = cJSON_CreateString(error_code);
    cJSON *message_json = cJSON_CreateString(message);

    cJSON_AddItemToObject(json, "code", code_json);
    cJSON_AddItemToObject(json, "message", message_json);

    if (reason) {
        cJSON *reason_json = cJSON_CreateString(reason);
        cJSON_AddItemToObject(json, "reason", reason_json);
    }

    char *json_string = cJSON_Print(json);
    esp_err_t ret = send_json_response(req, status_code, json_string);

    free(json_string);
    cJSON_Delete(json);

    return ret;
}

// Health endpoint - GET /health
static esp_err_t health_get_handler(httpd_req_t *req)
{
    return api_handle_health(req);
}

// Info endpoint - GET /info
static esp_err_t info_get_handler(httpd_req_t *req)
{
    return api_handle_info(req);
}

// Unlock endpoint - POST /unlock
static esp_err_t unlock_post_handler(httpd_req_t *req)
{
    return api_handle_unlock(req);
}

// WiFi configuration - POST /wifi (provisioning mode only)
static esp_err_t wifi_post_handler(httpd_req_t *req)
{
    if (!is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_READ_ONLY",
                                 "WiFi configuration not allowed in signing mode",
                                 "DEVICE_IN_SIGNING_MODE");
    }

    return api_handle_wifi_config(req);
}

// Auth configuration - POST /auth (provisioning mode only)
static esp_err_t auth_post_handler(httpd_req_t *req)
{
    if (!is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_READ_ONLY",
                                 "Auth configuration not allowed in signing mode",
                                 "DEVICE_IN_SIGNING_MODE");
    }

    return api_handle_auth_config(req);
}

// Key configuration - POST /key (provisioning mode only)
static esp_err_t key_post_handler(httpd_req_t *req)
{
    if (!is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_READ_ONLY",
                                 "Key configuration not allowed in signing mode",
                                 "DEVICE_IN_SIGNING_MODE");
    }

    return api_handle_key_config(req);
}

// Policy configuration - POST /policy (provisioning mode only)
static esp_err_t policy_post_handler(httpd_req_t *req)
{
    if (!is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_READ_ONLY",
                                 "Policy configuration not allowed in signing mode",
                                 "DEVICE_IN_SIGNING_MODE");
    }

    return api_handle_policy_config(req);
}

// Wipe configuration - POST /wipe (provisioning mode only)
static esp_err_t wipe_post_handler(httpd_req_t *req)
{
    if (!is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_READ_ONLY",
                                 "Wipe not allowed in signing mode",
                                 "DEVICE_IN_SIGNING_MODE");
    }

    return api_handle_wipe(req);
}

// EIP-1559 signing - POST /sign/eip1559 (signing mode only)
static esp_err_t sign_eip1559_post_handler(httpd_req_t *req)
{
    if (is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_PROVISIONING",
                                 "Signing not allowed in provisioning mode",
                                 "DEVICE_IN_PROVISIONING_MODE");
    }

    return api_handle_sign_eip1559(req);
}

// EIP-155 signing - POST /sign/eip155 (signing mode only)
static esp_err_t sign_eip155_post_handler(httpd_req_t *req)
{
    if (is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_PROVISIONING",
                                 "Signing not allowed in provisioning mode",
                                 "DEVICE_IN_PROVISIONING_MODE");
    }

    return api_handle_sign_eip155(req);
}

// Root page handler - GET /
static esp_err_t root_get_handler(httpd_req_t *req)
{
    if (is_provisioning_mode()) {
        // Serve provisioning page
        httpd_resp_set_type(req, "text/html");
        return httpd_resp_send(req, provisioning_html, strlen(provisioning_html));
    } else {
        // Serve device status page
        cJSON *json = cJSON_CreateObject();
        cJSON *status = cJSON_CreateString("operational");
        cJSON *mode = cJSON_CreateString("signing");

        cJSON_AddItemToObject(json, "status", status);
        cJSON_AddItemToObject(json, "mode", mode);

        char *json_string = cJSON_Print(json);
        esp_err_t ret = send_json_response(req, 200, json_string);

        free(json_string);
        cJSON_Delete(json);
        return ret;
    }
}

// Reboot handler - POST /reboot (provisioning mode only)
static esp_err_t reboot_post_handler(httpd_req_t *req)
{
    if (!is_provisioning_mode()) {
        return send_error_response(req, 403, "MODE_READ_ONLY",
                                 "Reboot not allowed in signing mode",
                                 "DEVICE_IN_SIGNING_MODE");
    }

    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send(req, "Rebooting...", strlen("Rebooting..."));

    // Schedule reboot after response is sent
    esp_restart();

    return ESP_OK;
}

// OPTIONS handler for CORS
static esp_err_t options_handler(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

esp_err_t https_server_start(void)
{
    if (!is_provisioning_mode() && !wifi_is_connected()) {
        ESP_LOGE(TAG, "Cannot start HTTPS server - WiFi not connected");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Starting HTTPS server...");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.httpd.server_port = 443;
    conf.httpd.max_uri_handlers = 20;
    conf.httpd.max_resp_headers = 8;
    conf.httpd.stack_size = 8192;

    // Use self-signed certificate
    conf.servercert = server_cert_pem_start;
    conf.servercert_len = server_cert_pem_end - server_cert_pem_start;
    conf.prvtkey_pem = server_key_pem_start;
    conf.prvtkey_len = server_key_pem_end - server_key_pem_start;

    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGE(TAG, "Error starting HTTPS server: %s", esp_err_to_name(ret));
        return ret;
    }

    // Register URI handlers

    // Root page (both modes)
    httpd_uri_t root_uri = {
        .uri       = "/",
        .method    = HTTP_GET,
        .handler   = root_get_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &root_uri);

    // Public endpoints (both modes)
    httpd_uri_t health_uri = {
        .uri       = "/health",
        .method    = HTTP_GET,
        .handler   = health_get_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &health_uri);

    httpd_uri_t info_uri = {
        .uri       = "/info",
        .method    = HTTP_GET,
        .handler   = info_get_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &info_uri);

    httpd_uri_t unlock_uri = {
        .uri       = "/unlock",
        .method    = HTTP_POST,
        .handler   = unlock_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &unlock_uri);

    // Provisioning mode endpoints
    httpd_uri_t wifi_uri = {
        .uri       = "/wifi",
        .method    = HTTP_POST,
        .handler   = wifi_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &wifi_uri);

    httpd_uri_t auth_uri = {
        .uri       = "/auth",
        .method    = HTTP_POST,
        .handler   = auth_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &auth_uri);

    httpd_uri_t key_uri = {
        .uri       = "/key",
        .method    = HTTP_POST,
        .handler   = key_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &key_uri);

    httpd_uri_t policy_uri = {
        .uri       = "/policy",
        .method    = HTTP_POST,
        .handler   = policy_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &policy_uri);

    httpd_uri_t wipe_uri = {
        .uri       = "/wipe",
        .method    = HTTP_POST,
        .handler   = wipe_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &wipe_uri);

    httpd_uri_t reboot_uri = {
        .uri       = "/reboot",
        .method    = HTTP_POST,
        .handler   = reboot_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &reboot_uri);

    // Signing mode endpoints
    httpd_uri_t sign_eip1559_uri = {
        .uri       = "/sign/eip1559",
        .method    = HTTP_POST,
        .handler   = sign_eip1559_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &sign_eip1559_uri);

    httpd_uri_t sign_eip155_uri = {
        .uri       = "/sign/eip155",
        .method    = HTTP_POST,
        .handler   = sign_eip155_post_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &sign_eip155_uri);

    // CORS OPTIONS handler
    httpd_uri_t options_uri = {
        .uri       = "/*",
        .method    = HTTP_OPTIONS,
        .handler   = options_handler,
        .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &options_uri);

    char ip_str[16];
    if (wifi_get_ip_info(ip_str, sizeof(ip_str)) == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS server started successfully on https://%s:443", ip_str);
    } else {
        ESP_LOGI(TAG, "HTTPS server started successfully on port 443");
    }

    return ESP_OK;
}

esp_err_t https_server_stop(void)
{
    if (server) {
        httpd_ssl_stop(server);
        server = NULL;
        ESP_LOGI(TAG, "HTTPS server stopped");
    }
    return ESP_OK;
}