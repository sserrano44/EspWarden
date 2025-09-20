#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H

#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t https_server_start(void);
esp_err_t https_server_stop(void);

// Helper functions for API responses
esp_err_t send_json_response(httpd_req_t *req, int status_code, const char *json_data);
esp_err_t send_error_response(httpd_req_t *req, int status_code, const char *error_code,
                             const char *message, const char *reason);

#ifdef __cplusplus
}
#endif

#endif // HTTPS_SERVER_H