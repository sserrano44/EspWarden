#ifndef ESP32_SIGNER_H
#define ESP32_SIGNER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Device modes
typedef enum {
    DEVICE_MODE_PROVISIONING = 0,
    DEVICE_MODE_SIGNING = 1
} device_mode_t;

// GPIO pin for provisioning jumper
#define PROVISIONING_PIN_A GPIO_NUM_2

// Authentication and session
#define AUTH_KEY_SIZE 32
#define NONCE_SIZE 16
#define SESSION_TOKEN_SIZE 32
#define SESSION_TTL_SECONDS 60
#define HMAC_SIZE 32

// Rate limiting
#define DEFAULT_RATE_LIMIT 10  // requests per minute
#define MAX_FAILED_AUTH_ATTEMPTS 10

// Crypto constants
#define PRIVATE_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 64
#define ETHEREUM_ADDRESS_SIZE 20
#define SIGNATURE_R_SIZE 32
#define SIGNATURE_S_SIZE 32

// Policy limits
#define MAX_WHITELISTED_ADDRESSES 50
#define MAX_FUNCTION_SELECTORS 100
#define MAX_CHAINS 10

// Error codes
typedef enum {
    SIGNER_OK = 0,
    SIGNER_ERR_INVALID_MODE,
    SIGNER_ERR_AUTH_FAILED,
    SIGNER_ERR_RATE_LIMITED,
    SIGNER_ERR_POLICY_VIOLATION,
    SIGNER_ERR_INVALID_TRANSACTION,
    SIGNER_ERR_CRYPTO_FAILED,
    SIGNER_ERR_STORAGE_FAILED,
    SIGNER_ERR_NETWORK_FAILED,
    SIGNER_ERR_REPLAY_ATTACK,
    SIGNER_ERR_SESSION_EXPIRED
} signer_error_t;

// Policy structure
typedef struct {
    uint32_t allowed_chains[MAX_CHAINS];
    uint8_t num_chains;

    uint8_t to_whitelist[MAX_WHITELISTED_ADDRESSES][20];
    uint8_t num_whitelisted_addresses;

    uint8_t function_whitelist[MAX_FUNCTION_SELECTORS][4];
    uint8_t num_function_selectors;

    char max_value_wei[32];
    uint32_t max_gas_limit;
    char max_fee_per_gas_wei[32];
    bool allow_empty_data_to_whitelist;
} policy_t;

// Transaction structures
typedef struct {
    uint32_t chain_id;
    char nonce[32];
    char max_fee_per_gas[32];
    char max_priority_fee_per_gas[32];
    char gas_limit[32];
    uint8_t to[20];
    char value[32];
    uint8_t *data;
    size_t data_len;
} eip1559_tx_t;

typedef struct {
    uint32_t chain_id;
    char nonce[32];
    char gas_price[32];
    char gas_limit[32];
    uint8_t to[20];
    char value[32];
    uint8_t *data;
    size_t data_len;
} eip155_tx_t;

// Signature structure
typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;
} ecdsa_signature_t;

// Function declarations
esp_err_t signer_init(void);
device_mode_t get_device_mode(void);
const char* get_firmware_version(void);
esp_err_t get_device_info(char *json_response, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // ESP32_SIGNER_H