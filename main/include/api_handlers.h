#ifndef API_HANDLERS_H
#define API_HANDLERS_H

#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

// Public endpoints (both modes)
esp_err_t api_handle_health(httpd_req_t *req);
esp_err_t api_handle_info(httpd_req_t *req);
esp_err_t api_handle_unlock(httpd_req_t *req);

// Provisioning mode endpoints
esp_err_t api_handle_wifi_config(httpd_req_t *req);
esp_err_t api_handle_auth_config(httpd_req_t *req);
esp_err_t api_handle_key_config(httpd_req_t *req);
esp_err_t api_handle_policy_config(httpd_req_t *req);
esp_err_t api_handle_wipe(httpd_req_t *req);

// Signing mode endpoints
esp_err_t api_handle_sign_eip1559(httpd_req_t *req);
esp_err_t api_handle_sign_eip155(httpd_req_t *req);

#ifdef __cplusplus
}
#endif

#endif // API_HANDLERS_H