#include "esp_log.h"
#include "esp_random.h"
#include "crypto_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Trezor-crypto includes
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha3.h"
#include "rand.h"
#include "memzero.h"

static const char *TAG = "crypto_manager";

// Helper function to safely append data to fields buffer
static esp_err_t safe_fields_append(uint8_t *fields_buffer, size_t *fields_offset,
                                   const uint8_t *data, size_t data_len, size_t max_size) {
    if (*fields_offset + data_len > max_size) {
        ESP_LOGE(TAG, "Fields buffer overflow: need %zu bytes, have %zu", *fields_offset + data_len, max_size);
        return ESP_ERR_NO_MEM;
    }
    memcpy(&fields_buffer[*fields_offset], data, data_len);
    *fields_offset += data_len;
    return ESP_OK;
}

esp_err_t crypto_manager_init(void)
{
    ESP_LOGD(TAG, "Initializing crypto manager with trezor-crypto");

    // Initialize random number generator with ESP32 hardware RNG
    // trezor-crypto will use this for key generation
    random_reseed(esp_random());

    ESP_LOGD(TAG, "Crypto manager initialized successfully");
    return ESP_OK;
}

esp_err_t crypto_generate_private_key(uint8_t private_key[32])
{
    if (!private_key) {
        ESP_LOGE(TAG, "private_key buffer is NULL");
        return ESP_FAIL;
    }

    // Generate random bytes using ESP32 hardware RNG
    esp_fill_random(private_key, 32);

    // Ensure the private key is within the valid range for secp256k1
    // Private key must be between 1 and n-1 where n is the curve order
    // This is a simple check - in practice, the probability of generating
    // an invalid key is negligible (about 1 in 2^128)
    bool valid = false;
    for (int i = 0; i < 32; i++) {
        if (private_key[i] != 0) {
            valid = true;
            break;
        }
    }

    if (!valid) {
        ESP_LOGE(TAG, "Generated invalid private key (all zeros)");
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "Generated new secp256k1 private key");
    return ESP_OK;
}

esp_err_t crypto_get_public_key(const uint8_t private_key[32], uint8_t public_key[64])
{
    if (!private_key || !public_key) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_FAIL;
    }

    // Get the uncompressed public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
    uint8_t pubkey_full[65];
    ecdsa_get_public_key65(&secp256k1, private_key, pubkey_full);

    // Copy x and y coordinates (skip the 0x04 prefix)
    memcpy(public_key, &pubkey_full[1], 64);

    ESP_LOGD(TAG, "Derived public key from private key");
    return ESP_OK;
}

esp_err_t crypto_get_ethereum_address(const uint8_t public_key[64], uint8_t address[20])
{
    if (!public_key || !address) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_FAIL;
    }

    // Calculate Keccak-256 hash of the public key (64 bytes)
    uint8_t hash[32];
    keccak_256(public_key, 64, hash);

    // Ethereum address is the last 20 bytes of the hash
    memcpy(address, &hash[12], 20);

    ESP_LOGD(TAG, "Derived Ethereum address from public key");
    return ESP_OK;
}

esp_err_t crypto_sign_transaction(const uint8_t private_key[32],
                                 const transaction_hash_t *tx_hash,
                                 ecdsa_signature_t *signature)
{
    if (!private_key || !tx_hash || !signature) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_FAIL;
    }

    // Clear the output signature
    memzero(signature, sizeof(ecdsa_signature_t));

    ESP_LOGD(TAG, "Signing transaction hash");

    // Sign the transaction hash using secp256k1
    uint8_t sig[64];  // r (32 bytes) + s (32 bytes)
    uint8_t pby;      // Recovery ID

    int result = ecdsa_sign_digest(&secp256k1, private_key, tx_hash->hash, sig, &pby, NULL);
    if (result != 0) {
        ESP_LOGE(TAG, "ECDSA signing failed");
        return ESP_FAIL;
    }

    // Copy r and s components
    memcpy(signature->r, &sig[0], 32);
    memcpy(signature->s, &sig[32], 32);

    // Calculate v based on transaction type
    if (tx_hash->tx_type == 2) {
        // EIP-1559 transaction: v is just the recovery ID (0 or 1)
        signature->v = pby;
    } else if (tx_hash->chain_id == 0) {
        // Legacy transaction (pre-EIP-155)
        signature->v = pby + 27;
    } else {
        // EIP-155 transaction
        signature->v = pby + 35 + 2 * tx_hash->chain_id;
    }

    ESP_LOGD(TAG, "Transaction signed successfully (chain_id=%lu, tx_type=%d, recovery_id=%d, v=%d)",
             tx_hash->chain_id, tx_hash->tx_type, pby, signature->v);
    return ESP_OK;
}

esp_err_t crypto_verify_signature(const uint8_t public_key[64],
                                 const uint8_t hash[32],
                                 const ecdsa_signature_t *signature)
{
    if (!public_key || !hash || !signature) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_FAIL;
    }

    // Prepare the signature in trezor-crypto format (64 bytes: r + s)
    uint8_t sig[64];
    memcpy(&sig[0], signature->r, 32);
    memcpy(&sig[32], signature->s, 32);

    // Prepare the public key in compressed format for verification
    uint8_t pubkey_compressed[33];
    pubkey_compressed[0] = 0x02 + (public_key[63] & 1);  // 0x02 or 0x03 based on y parity
    memcpy(&pubkey_compressed[1], public_key, 32);       // x coordinate

    int result = ecdsa_verify_digest(&secp256k1, pubkey_compressed, sig, hash);
    if (result != 0) {
        ESP_LOGD(TAG, "Signature verification successful");
        return ESP_OK;
    } else {
        ESP_LOGW(TAG, "Signature verification failed");
        return ESP_FAIL;
    }
}

// Helper function to convert hex string to bytes (variable length)
static esp_err_t hex_to_bytes_crypto(const char *hex_str, uint8_t *bytes, size_t max_len)
{
    // Comprehensive input validation
    if (!hex_str || !bytes || max_len == 0) {
        ESP_LOGE(TAG, "Invalid parameters for hex conversion");
        return ESP_ERR_INVALID_ARG;
    }

    size_t hex_len = strlen(hex_str);

    // Check for reasonable string length limits (prevent DoS)
    if (hex_len > 1024 || hex_len == 0) {
        ESP_LOGE(TAG, "Hex string length invalid: %zu", hex_len);
        return ESP_ERR_INVALID_SIZE;
    }

    // Handle 0x prefix
    const char *start = hex_str;
    if (hex_len > 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
        start = hex_str + 2;
        hex_len -= 2;
    }

    // Check if hex length is even and not too long
    if (hex_len % 2 != 0) {
        ESP_LOGE(TAG, "Hex string has odd length: %zu", hex_len);
        return ESP_ERR_INVALID_ARG;
    }

    if (hex_len > max_len * 2) {
        ESP_LOGE(TAG, "Hex string too long: %zu > %zu", hex_len, max_len * 2);
        return ESP_ERR_INVALID_SIZE;
    }

    // Clear output buffer
    memset(bytes, 0, max_len);

    // Parse hex bytes into the end of the buffer (big-endian)
    size_t byte_count = hex_len / 2;
    size_t offset = max_len - byte_count;

    for (size_t i = 0; i < byte_count; i++) {
        char byte_str[3] = {start[i * 2], start[i * 2 + 1], '\0'};

        // Validate hex characters
        if (!isxdigit((unsigned char)byte_str[0]) || !isxdigit((unsigned char)byte_str[1])) {
            ESP_LOGE(TAG, "Invalid hex character at position %zu", i * 2);
            return ESP_ERR_INVALID_ARG;
        }

        char *endptr;
        long val = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0' || val < 0 || val > 255) {
            ESP_LOGE(TAG, "Invalid hex byte value: %ld", val);
            return ESP_ERR_INVALID_ARG;
        }
        bytes[offset + i] = (uint8_t)val;
    }
    return ESP_OK;
}

// Helper function to encode big-endian integer as minimal RLP bytes
static size_t encode_rlp_int(uint64_t value, uint8_t *buffer)
{
    if (value == 0) {
        buffer[0] = 0x80; // Empty string encoding for zero
        return 1;
    }

    // Find number of bytes needed
    uint8_t bytes[8];
    size_t len = 0;
    uint64_t temp = value;
    while (temp > 0) {
        bytes[len++] = (uint8_t)(temp & 0xFF);
        temp >>= 8;
    }

    // Reverse to big-endian
    for (size_t i = 0; i < len; i++) {
        buffer[i] = bytes[len - 1 - i];
    }

    return len;
}

// Helper function to encode RLP length prefix
static size_t encode_rlp_length(size_t length, uint8_t *buffer, bool is_list)
{
    uint8_t base = is_list ? 0xc0 : 0x80;

    if (length < 56) {
        buffer[0] = base + length;
        return 1;
    } else {
        // Long form
        size_t len_bytes = 0;
        size_t temp = length;
        while (temp > 0) {
            len_bytes++;
            temp >>= 8;
        }

        buffer[0] = base + 55 + len_bytes;

        for (size_t i = 0; i < len_bytes; i++) {
            buffer[1 + i] = (uint8_t)(length >> (8 * (len_bytes - 1 - i)));
        }

        return 1 + len_bytes;
    }
}

esp_err_t crypto_hash_eip1559_transaction(const eip1559_tx_t *tx, transaction_hash_t *tx_hash)
{
    // Comprehensive input validation
    if (!tx || !tx_hash) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate transaction fields are not empty
    if (tx->nonce[0] == '\0' || tx->max_priority_fee_per_gas[0] == '\0' ||
        tx->max_fee_per_gas[0] == '\0' || tx->gas_limit[0] == '\0' || tx->value[0] == '\0') {
        ESP_LOGE(TAG, "Required transaction fields are empty");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate chain ID range (prevent unreasonable values)
    if (tx->chain_id == 0 || tx->chain_id > 0xFFFFFFFF) {
        ESP_LOGE(TAG, "Invalid chain ID: %lu", tx->chain_id);
        return ESP_ERR_INVALID_ARG;
    }

    // Validate data length if data is provided
    if (tx->data && tx->data_len > 65536) {  // 64KB limit
        ESP_LOGE(TAG, "Transaction data too large: %u bytes", tx->data_len);
        return ESP_ERR_INVALID_SIZE;
    }

    // Validate string field lengths
    if (strlen(tx->nonce) > 128 || strlen(tx->max_priority_fee_per_gas) > 128 ||
        strlen(tx->max_fee_per_gas) > 128 || strlen(tx->gas_limit) > 128 ||
        strlen(tx->value) > 128) {
        ESP_LOGE(TAG, "Transaction field string too long");
        return ESP_ERR_INVALID_SIZE;
    }

    // Debug: Log incoming transaction data

    // RLP encoding buffers with bounds checking
    // Maximum transaction size: type(1) + list_header(3) + fields(~300) = ~304 bytes
    #define MAX_RLP_SIZE 512
    #define MAX_FIELDS_SIZE 400

    static uint8_t rlp_data[MAX_RLP_SIZE];
    static uint8_t fields_buffer[MAX_FIELDS_SIZE];
    static SemaphoreHandle_t crypto_mutex = NULL;

    // Initialize mutex on first use
    if (crypto_mutex == NULL) {
        crypto_mutex = xSemaphoreCreateMutex();
        if (crypto_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create crypto mutex");
            return ESP_ERR_NO_MEM;
        }
    }

    // Take mutex for thread safety
    if (xSemaphoreTake(crypto_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire crypto mutex");
        return ESP_ERR_TIMEOUT;
    }

    size_t offset = 0;
    size_t fields_offset = 0;

    // Temporary buffers for field encoding
    uint8_t field_buffer[64];
    uint8_t len_prefix_buffer[8];
    size_t field_len, len_prefix;

    // Include the 0x02 prefix for EIP-1559 transaction hash calculation
    if (offset >= MAX_RLP_SIZE) {
        xSemaphoreGive(crypto_mutex);
        return ESP_ERR_NO_MEM;
    }
    rlp_data[offset++] = 0x02;

    // Field 1: chainId
    field_len = encode_rlp_int(tx->chain_id, field_buffer);
    len_prefix = encode_rlp_length(field_len, len_prefix_buffer, false);

    if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
        safe_fields_append(fields_buffer, &fields_offset, field_buffer, field_len, MAX_FIELDS_SIZE) != ESP_OK) {
        xSemaphoreGive(crypto_mutex);
        return ESP_ERR_NO_MEM;
    }

    // Field 2: nonce (hex string to bytes)
    uint8_t nonce_bytes[32];
    if (hex_to_bytes_crypto(tx->nonce, nonce_bytes, 32) == ESP_OK) {
        // Find the starting position (skip leading zeros)
        size_t start = 0;
        while (start < 32 && nonce_bytes[start] == 0) start++;

        if (start == 32) {
            // All zeros - encode as empty string (0x80)
            uint8_t zero_byte = 0x80;
            if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        } else {
            // Non-zero value - encode the remaining bytes
            size_t actual_len = 32 - start;

            // For single byte values < 128, encode directly without RLP length prefix
            if (actual_len == 1 && nonce_bytes[start] < 0x80) {
                if (safe_fields_append(fields_buffer, &fields_offset, &nonce_bytes[start], 1, MAX_FIELDS_SIZE) != ESP_OK) {
                    xSemaphoreGive(crypto_mutex);
                    return ESP_ERR_NO_MEM;
                }
            } else {
                // Multi-byte or >= 128: use RLP string encoding
                len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
                if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
                    safe_fields_append(fields_buffer, &fields_offset, &nonce_bytes[start], actual_len, MAX_FIELDS_SIZE) != ESP_OK) {
                    xSemaphoreGive(crypto_mutex);
                    return ESP_ERR_NO_MEM;
                }
            }
        }
    } else {
        // Fallback: encode as zero
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 3: maxPriorityFeePerGas
    uint8_t priority_fee[32];
    if (hex_to_bytes_crypto(tx->max_priority_fee_per_gas, priority_fee, 32) == ESP_OK) {
        // Remove leading zeros
        size_t start = 0;
        while (start < 32 && priority_fee[start] == 0) start++;
        if (start == 32) start = 31; // Keep at least one byte

        size_t actual_len = 32 - start;

        // For single byte values < 128, encode directly without RLP length prefix
        if (actual_len == 1 && priority_fee[start] < 0x80) {
            if (safe_fields_append(fields_buffer, &fields_offset, &priority_fee[start], 1, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        } else {
            // Multi-byte or >= 128: use RLP string encoding
            len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
            if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
                safe_fields_append(fields_buffer, &fields_offset, &priority_fee[start], actual_len, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        }
    } else {
        ESP_LOGE(TAG, "Failed to parse maxPriorityFeePerGas: %s", tx->max_priority_fee_per_gas);
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 4: maxFeePerGas
    uint8_t max_fee[32];
    if (hex_to_bytes_crypto(tx->max_fee_per_gas, max_fee, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && max_fee[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;

        // For single byte values < 128, encode directly without RLP length prefix
        if (actual_len == 1 && max_fee[start] < 0x80) {
            if (safe_fields_append(fields_buffer, &fields_offset, &max_fee[start], 1, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        } else {
            // Multi-byte or >= 128: use RLP string encoding
            len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
            if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
                safe_fields_append(fields_buffer, &fields_offset, &max_fee[start], actual_len, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        }
    } else {
        ESP_LOGE(TAG, "Failed to parse maxFeePerGas: %s", tx->max_fee_per_gas);
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 5: gasLimit (convert from hex string)
    uint64_t gas_limit_val = strtoull(tx->gas_limit, NULL, 0);
    field_len = encode_rlp_int(gas_limit_val, field_buffer);

    // For single byte values < 128, encode directly without RLP length prefix
    if (field_len == 1 && field_buffer[0] < 0x80) {
        if (safe_fields_append(fields_buffer, &fields_offset, field_buffer, 1, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    } else {
        // Multi-byte or >= 128: use RLP string encoding
        len_prefix = encode_rlp_length(field_len, len_prefix_buffer, false);
        if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
            safe_fields_append(fields_buffer, &fields_offset, field_buffer, field_len, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 6: to (20 bytes) - directly use the bytes since to is already uint8_t[20]
    len_prefix = encode_rlp_length(20, len_prefix_buffer, false);
    if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
        safe_fields_append(fields_buffer, &fields_offset, tx->to, 20, MAX_FIELDS_SIZE) != ESP_OK) {
        xSemaphoreGive(crypto_mutex);
        return ESP_ERR_NO_MEM;
    }

    // Field 7: value
    uint8_t value_bytes[32];
    if (hex_to_bytes_crypto(tx->value, value_bytes, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && value_bytes[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;

        // For single byte values < 128, encode directly without RLP length prefix
        if (actual_len == 1 && value_bytes[start] < 0x80) {
            if (safe_fields_append(fields_buffer, &fields_offset, &value_bytes[start], 1, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        } else {
            // Multi-byte or >= 128: use RLP string encoding
            len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
            if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
                safe_fields_append(fields_buffer, &fields_offset, &value_bytes[start], actual_len, MAX_FIELDS_SIZE) != ESP_OK) {
                xSemaphoreGive(crypto_mutex);
                return ESP_ERR_NO_MEM;
            }
        }
    } else {
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 8: data (use data_len since data is already uint8_t*)
    if (tx->data && tx->data_len > 0) {
        len_prefix = encode_rlp_length(tx->data_len, len_prefix_buffer, false);
        if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE) != ESP_OK ||
            safe_fields_append(fields_buffer, &fields_offset, tx->data, tx->data_len, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    } else {
        uint8_t zero_byte = 0x80; // Empty string
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE) != ESP_OK) {
            xSemaphoreGive(crypto_mutex);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 9: accessList (empty for now)
    uint8_t empty_list = 0xc0; // Empty list
    if (safe_fields_append(fields_buffer, &fields_offset, &empty_list, 1, MAX_FIELDS_SIZE) != ESP_OK) {
        xSemaphoreGive(crypto_mutex);
        return ESP_ERR_NO_MEM;
    }

    // Encode the list length and assemble final transaction
    size_t list_len_prefix = encode_rlp_length(fields_offset, field_buffer, true);

    // Copy list length prefix to main buffer
    memcpy(&rlp_data[offset], field_buffer, list_len_prefix);
    offset += list_len_prefix;

    // Copy all fields to main buffer with bounds checking
    if (offset + fields_offset > MAX_RLP_SIZE) {
        ESP_LOGE(TAG, "RLP buffer overflow: need %zu bytes, have %d", offset + fields_offset, MAX_RLP_SIZE);
        xSemaphoreGive(crypto_mutex);
        return ESP_ERR_NO_MEM;
    }
    memcpy(&rlp_data[offset], fields_buffer, fields_offset);
    offset += fields_offset;


    // Calculate Keccak-256 hash
    keccak_256(rlp_data, offset, tx_hash->hash);


    tx_hash->chain_id = tx->chain_id;
    tx_hash->tx_type = 2; // EIP-1559 transaction type

    // Release mutex
    xSemaphoreGive(crypto_mutex);

    ESP_LOGD(TAG, "EIP-1559 transaction hash calculated (chain_id=%lu)", tx->chain_id);
    return ESP_OK;
}

esp_err_t crypto_hash_eip155_transaction(const eip155_tx_t *tx, transaction_hash_t *tx_hash)
{
    // Comprehensive input validation
    if (!tx || !tx_hash) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate transaction fields are not empty
    if (tx->nonce[0] == '\0' || tx->gas_price[0] == '\0' ||
        tx->gas_limit[0] == '\0' || tx->value[0] == '\0') {
        ESP_LOGE(TAG, "Required transaction fields are empty");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate chain ID range
    if (tx->chain_id == 0 || tx->chain_id > 0xFFFFFFFF) {
        ESP_LOGE(TAG, "Invalid chain ID: %lu", tx->chain_id);
        return ESP_ERR_INVALID_ARG;
    }

    // Validate data length if data is provided
    if (tx->data && tx->data_len > 65536) {  // 64KB limit
        ESP_LOGE(TAG, "Transaction data too large: %u bytes", tx->data_len);
        return ESP_ERR_INVALID_SIZE;
    }

    // Validate string field lengths
    if (strlen(tx->nonce) > 128 || strlen(tx->gas_price) > 128 ||
        strlen(tx->gas_limit) > 128 || strlen(tx->value) > 128) {
        ESP_LOGE(TAG, "Transaction field string too long");
        return ESP_ERR_INVALID_SIZE;
    }

    // RLP encoding buffers with bounds checking
    #define MAX_RLP_SIZE_155 512
    #define MAX_FIELDS_SIZE_155 400

    static uint8_t rlp_data[MAX_RLP_SIZE_155];
    static uint8_t fields_buffer[MAX_FIELDS_SIZE_155];
    static SemaphoreHandle_t crypto_mutex_155 = NULL;

    // Initialize mutex on first use
    if (crypto_mutex_155 == NULL) {
        crypto_mutex_155 = xSemaphoreCreateMutex();
        if (crypto_mutex_155 == NULL) {
            ESP_LOGE(TAG, "Failed to create crypto mutex for EIP-155");
            return ESP_ERR_NO_MEM;
        }
    }

    // Take mutex for thread safety
    if (xSemaphoreTake(crypto_mutex_155, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire crypto mutex for EIP-155");
        return ESP_ERR_TIMEOUT;
    }

    size_t offset = 0;
    size_t fields_offset = 0;
    uint8_t field_buffer[64];
    uint8_t len_prefix_buffer[8];
    size_t field_len, len_prefix;

    // Field 1: nonce
    uint8_t nonce_bytes[32];
    if (hex_to_bytes_crypto(tx->nonce, nonce_bytes, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && nonce_bytes[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
        if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
            safe_fields_append(fields_buffer, &fields_offset, &nonce_bytes[start], actual_len, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    } else {
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 2: gasPrice
    uint8_t gas_price[32];
    if (hex_to_bytes_crypto(tx->gas_price, gas_price, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && gas_price[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
        if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
            safe_fields_append(fields_buffer, &fields_offset, &gas_price[start], actual_len, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    } else {
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 3: gasLimit (convert from hex string)
    uint64_t gas_limit_val = strtoull(tx->gas_limit, NULL, 0);
    field_len = encode_rlp_int(gas_limit_val, field_buffer);
    len_prefix = encode_rlp_length(field_len, len_prefix_buffer, false);
    if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
        safe_fields_append(fields_buffer, &fields_offset, field_buffer, field_len, MAX_FIELDS_SIZE_155) != ESP_OK) {
        xSemaphoreGive(crypto_mutex_155);
        return ESP_ERR_NO_MEM;
    }

    // Field 4: to (directly use the bytes since to is already uint8_t[20])
    len_prefix = encode_rlp_length(20, len_prefix_buffer, false);
    if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
        safe_fields_append(fields_buffer, &fields_offset, tx->to, 20, MAX_FIELDS_SIZE_155) != ESP_OK) {
        xSemaphoreGive(crypto_mutex_155);
        return ESP_ERR_NO_MEM;
    }

    // Field 5: value
    uint8_t value_bytes[32];
    if (hex_to_bytes_crypto(tx->value, value_bytes, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && value_bytes[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, len_prefix_buffer, false);
        if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
            safe_fields_append(fields_buffer, &fields_offset, &value_bytes[start], actual_len, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    } else {
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    }

    // Field 6: data (use data_len since data is already uint8_t*)
    if (tx->data && tx->data_len > 0) {
        len_prefix = encode_rlp_length(tx->data_len, len_prefix_buffer, false);
        if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
            safe_fields_append(fields_buffer, &fields_offset, tx->data, tx->data_len, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    } else {
        uint8_t zero_byte = 0x80;
        if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE_155) != ESP_OK) {
            xSemaphoreGive(crypto_mutex_155);
            return ESP_ERR_NO_MEM;
        }
    }

    // EIP-155: Add chain_id, 0, 0 for replay protection
    field_len = encode_rlp_int(tx->chain_id, field_buffer);
    len_prefix = encode_rlp_length(field_len, len_prefix_buffer, false);
    if (safe_fields_append(fields_buffer, &fields_offset, len_prefix_buffer, len_prefix, MAX_FIELDS_SIZE_155) != ESP_OK ||
        safe_fields_append(fields_buffer, &fields_offset, field_buffer, field_len, MAX_FIELDS_SIZE_155) != ESP_OK) {
        xSemaphoreGive(crypto_mutex_155);
        return ESP_ERR_NO_MEM;
    }

    // Two empty values for EIP-155
    uint8_t zero_byte = 0x80;
    if (safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE_155) != ESP_OK ||  // Empty r
        safe_fields_append(fields_buffer, &fields_offset, &zero_byte, 1, MAX_FIELDS_SIZE_155) != ESP_OK) {  // Empty s
        xSemaphoreGive(crypto_mutex_155);
        return ESP_ERR_NO_MEM;
    }

    // Encode list length and assemble final transaction
    size_t list_len_prefix = encode_rlp_length(fields_offset, field_buffer, true);

    // Copy list length prefix to main buffer
    if (offset + list_len_prefix > MAX_RLP_SIZE_155) {
        ESP_LOGE(TAG, "RLP buffer overflow for list prefix");
        xSemaphoreGive(crypto_mutex_155);
        return ESP_ERR_NO_MEM;
    }
    memcpy(&rlp_data[offset], field_buffer, list_len_prefix);
    offset += list_len_prefix;

    // Copy all fields to main buffer with bounds checking
    if (offset + fields_offset > MAX_RLP_SIZE_155) {
        ESP_LOGE(TAG, "RLP buffer overflow: need %zu bytes, have %d", offset + fields_offset, MAX_RLP_SIZE_155);
        xSemaphoreGive(crypto_mutex_155);
        return ESP_ERR_NO_MEM;
    }
    memcpy(&rlp_data[offset], fields_buffer, fields_offset);
    offset += fields_offset;

    // Calculate Keccak-256 hash
    keccak_256(rlp_data, offset, tx_hash->hash);
    tx_hash->chain_id = tx->chain_id;
    tx_hash->tx_type = 0; // Legacy/EIP-155 transaction type

    // Release mutex
    xSemaphoreGive(crypto_mutex_155);

    ESP_LOGD(TAG, "EIP-155 transaction hash calculated (chain_id=%lu)", tx->chain_id);
    return ESP_OK;
}