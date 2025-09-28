#include "captive_dns.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "device_mode.h"
#include <string.h>

static const char *TAG = "CAPTIVE_DNS";

#define DNS_PORT 53
#define DNS_MAX_LEN 512
#define AP_IP 0x0104A8C0  // 192.168.4.1 in network byte order

static int dns_socket = -1;
static TaskHandle_t dns_task_handle = NULL;

// Simple DNS response for captive portal
static void send_dns_response(int sock, struct sockaddr_in *client_addr, uint8_t *query, int query_len)
{
    if (query_len < 12) return; // Invalid DNS query

    uint8_t response[DNS_MAX_LEN];
    memcpy(response, query, query_len);

    // Set response flags
    response[2] = 0x81; // Response, Authoritative
    response[3] = 0x80; // No error

    // Answer count = 1
    response[6] = 0x00;
    response[7] = 0x01;

    int response_len = query_len;

    // Add answer section
    // Name pointer to question
    response[response_len++] = 0xC0;
    response[response_len++] = 0x0C;

    // Type A
    response[response_len++] = 0x00;
    response[response_len++] = 0x01;

    // Class IN
    response[response_len++] = 0x00;
    response[response_len++] = 0x01;

    // TTL (60 seconds)
    response[response_len++] = 0x00;
    response[response_len++] = 0x00;
    response[response_len++] = 0x00;
    response[response_len++] = 0x3C;

    // Data length
    response[response_len++] = 0x00;
    response[response_len++] = 0x04;

    // IP address (192.168.4.1)
    response[response_len++] = 192;
    response[response_len++] = 168;
    response[response_len++] = 4;
    response[response_len++] = 1;

    sendto(sock, response, response_len, 0, (struct sockaddr*)client_addr, sizeof(*client_addr));
}

static void dns_server_task(void *pvParameters)
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    uint8_t buffer[DNS_MAX_LEN];

    // Create UDP socket
    dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_socket < 0) {
        ESP_LOGE(TAG, "Failed to create DNS socket");
        vTaskDelete(NULL);
        return;
    }

    // Bind to DNS port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(dns_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind DNS socket");
        close(dns_socket);
        dns_socket = -1;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS server started on port %d", DNS_PORT);

    while (is_provisioning_mode()) {
        int len = recvfrom(dns_socket, buffer, sizeof(buffer), 0,
                          (struct sockaddr*)&client_addr, &client_addr_len);

        if (len > 0) {
            ESP_LOGD(TAG, "DNS query received from %s",
                    inet_ntoa(client_addr.sin_addr));
            send_dns_response(dns_socket, &client_addr, buffer, len);
        }
    }

    ESP_LOGI(TAG, "DNS server stopping");
    close(dns_socket);
    dns_socket = -1;
    vTaskDelete(NULL);
}

esp_err_t captive_dns_start(void)
{
    if (!is_provisioning_mode()) {
        return ESP_ERR_INVALID_STATE;
    }

    if (dns_task_handle != NULL) {
        ESP_LOGW(TAG, "DNS server already running");
        return ESP_OK;
    }

    BaseType_t ret = xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5, &dns_task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create DNS server task");
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t captive_dns_stop(void)
{
    if (dns_task_handle != NULL) {
        vTaskDelete(dns_task_handle);
        dns_task_handle = NULL;
    }

    if (dns_socket >= 0) {
        close(dns_socket);
        dns_socket = -1;
    }

    return ESP_OK;
}