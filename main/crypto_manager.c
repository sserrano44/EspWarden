#include "esp_log.h"
#include "esp_random.h"
#include "crypto_manager.h"
#include <string.h>
#include <stdlib.h>

// Trezor-crypto includes
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha3.h"
#include "rand.h"
#include "memzero.h"

static const char *TAG = "crypto_manager";

esp_err_t crypto_manager_init(void)
{
    ESP_LOGI(TAG, "Initializing crypto manager with trezor-crypto");

    // Initialize random number generator with ESP32 hardware RNG
    // trezor-crypto will use this for key generation
    random_reseed(esp_random());

    ESP_LOGI(TAG, "Crypto manager initialized successfully");
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

    ESP_LOGI(TAG, "Generated new secp256k1 private key");
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

    // Calculate v for Ethereum (EIP-155)
    // v = recovery_id + 27 + 2 * chain_id (for EIP-155)
    if (tx_hash->chain_id == 0) {
        // Legacy transaction (pre-EIP-155)
        signature->v = pby + 27;
    } else {
        // EIP-155 transaction
        signature->v = pby + 35 + 2 * tx_hash->chain_id;
    }

    ESP_LOGI(TAG, "Transaction signed successfully (chain_id=%lu, v=%d)",
             tx_hash->chain_id, signature->v);
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

// Helper function to convert hex string to bytes
static esp_err_t hex_to_bytes_crypto(const char *hex_str, uint8_t *bytes, size_t expected_len)
{
    if (!hex_str || !bytes) return ESP_FAIL;

    size_t hex_len = strlen(hex_str);

    // Handle 0x prefix
    const char *start = hex_str;
    if (hex_len > 2 && hex_str[0] == '0' && hex_str[1] == 'x') {
        start = hex_str + 2;
        hex_len -= 2;
    }

    if (hex_len != expected_len * 2) return ESP_FAIL;

    for (size_t i = 0; i < expected_len; i++) {
        char byte_str[3] = {start[i * 2], start[i * 2 + 1], '\0'};
        char *endptr;
        long val = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0' || val < 0 || val > 255) return ESP_FAIL;
        bytes[i] = (uint8_t)val;
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
    if (!tx || !tx_hash) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_FAIL;
    }

    // RLP encoding buffer (should be large enough for any transaction)
    uint8_t rlp_data[1024];
    size_t offset = 0;

    // Temporary buffers for field encoding
    uint8_t field_buffer[64];

    // Start with EIP-2718 transaction type (0x02 for EIP-1559)
    rlp_data[offset++] = 0x02;

    // We'll come back to set the list length
    size_t list_length_offset = offset;
    offset += 8; // Reserve space for length encoding
    size_t fields_start = offset;

    // Field 1: chainId
    size_t field_len = encode_rlp_int(tx->chain_id, field_buffer);
    size_t len_prefix = encode_rlp_length(field_len, &rlp_data[offset], false);
    offset += len_prefix;
    memcpy(&rlp_data[offset], field_buffer, field_len);
    offset += field_len;

    // Field 2: nonce (hex string to bytes)
    uint8_t nonce_bytes[32];
    size_t nonce_len = 0;
    if (hex_to_bytes_crypto(tx->nonce, nonce_bytes, 32) == ESP_OK) {
        // Find actual length (remove leading zeros)
        while (nonce_len < 32 && nonce_bytes[nonce_len] == 0) nonce_len++;
        if (nonce_len == 32) nonce_len = 1; // Keep at least one byte
        else nonce_len = 32 - nonce_len;

        len_prefix = encode_rlp_length(nonce_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &nonce_bytes[32 - nonce_len], nonce_len);
        offset += nonce_len;
    } else {
        // Fallback: encode as zero
        rlp_data[offset++] = 0x80;
    }

    // Field 3: maxPriorityFeePerGas
    uint8_t priority_fee[32];
    if (hex_to_bytes_crypto(tx->max_priority_fee_per_gas, priority_fee, 32) == ESP_OK) {
        // Remove leading zeros
        size_t start = 0;
        while (start < 32 && priority_fee[start] == 0) start++;
        if (start == 32) start = 31; // Keep at least one byte

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &priority_fee[start], actual_len);
        offset += actual_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // Field 4: maxFeePerGas
    uint8_t max_fee[32];
    if (hex_to_bytes_crypto(tx->max_fee_per_gas, max_fee, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && max_fee[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &max_fee[start], actual_len);
        offset += actual_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // Field 5: gasLimit (convert from hex string)
    uint64_t gas_limit_val = strtoull(tx->gas_limit, NULL, 0);
    field_len = encode_rlp_int(gas_limit_val, field_buffer);
    len_prefix = encode_rlp_length(field_len, &rlp_data[offset], false);
    offset += len_prefix;
    memcpy(&rlp_data[offset], field_buffer, field_len);
    offset += field_len;

    // Field 6: to (20 bytes) - directly use the bytes since to is already uint8_t[20]
    len_prefix = encode_rlp_length(20, &rlp_data[offset], false);
    offset += len_prefix;
    memcpy(&rlp_data[offset], tx->to, 20);
    offset += 20;

    // Field 7: value
    uint8_t value_bytes[32];
    if (hex_to_bytes_crypto(tx->value, value_bytes, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && value_bytes[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &value_bytes[start], actual_len);
        offset += actual_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // Field 8: data (use data_len since data is already uint8_t*)
    if (tx->data && tx->data_len > 0) {
        len_prefix = encode_rlp_length(tx->data_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], tx->data, tx->data_len);
        offset += tx->data_len;
    } else {
        rlp_data[offset++] = 0x80; // Empty string
    }

    // Field 9: accessList (empty for now)
    rlp_data[offset++] = 0xc0; // Empty list

    // Now encode the list length
    size_t fields_length = offset - fields_start;
    size_t actual_len_prefix = encode_rlp_length(fields_length, field_buffer, true);

    // Move data to make room for proper length prefix
    memmove(&rlp_data[list_length_offset + actual_len_prefix], &rlp_data[fields_start], fields_length);
    memcpy(&rlp_data[list_length_offset], field_buffer, actual_len_prefix);
    offset = list_length_offset + actual_len_prefix + fields_length;

    // Calculate Keccak-256 hash
    keccak_256(rlp_data, offset, tx_hash->hash);
    tx_hash->chain_id = tx->chain_id;

    ESP_LOGI(TAG, "EIP-1559 transaction hash calculated (chain_id=%lu)", tx->chain_id);
    return ESP_OK;
}

esp_err_t crypto_hash_eip155_transaction(const eip155_tx_t *tx, transaction_hash_t *tx_hash)
{
    if (!tx || !tx_hash) {
        ESP_LOGE(TAG, "NULL pointer provided");
        return ESP_FAIL;
    }

    // RLP encoding buffer
    uint8_t rlp_data[1024];
    size_t offset = 0;
    uint8_t field_buffer[64];

    // Reserve space for list length
    size_t list_length_offset = offset;
    offset += 8;
    size_t fields_start = offset;

    // Field 1: nonce
    uint8_t nonce_bytes[32];
    if (hex_to_bytes_crypto(tx->nonce, nonce_bytes, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && nonce_bytes[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        size_t len_prefix = encode_rlp_length(actual_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &nonce_bytes[start], actual_len);
        offset += actual_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // Field 2: gasPrice
    uint8_t gas_price[32];
    if (hex_to_bytes_crypto(tx->gas_price, gas_price, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && gas_price[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        size_t len_prefix = encode_rlp_length(actual_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &gas_price[start], actual_len);
        offset += actual_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // Field 3: gasLimit (convert from hex string)
    uint64_t gas_limit_val = strtoull(tx->gas_limit, NULL, 0);
    size_t field_len = encode_rlp_int(gas_limit_val, field_buffer);
    size_t len_prefix = encode_rlp_length(field_len, &rlp_data[offset], false);
    offset += len_prefix;
    memcpy(&rlp_data[offset], field_buffer, field_len);
    offset += field_len;

    // Field 4: to (directly use the bytes since to is already uint8_t[20])
    len_prefix = encode_rlp_length(20, &rlp_data[offset], false);
    offset += len_prefix;
    memcpy(&rlp_data[offset], tx->to, 20);
    offset += 20;

    // Field 5: value
    uint8_t value_bytes[32];
    if (hex_to_bytes_crypto(tx->value, value_bytes, 32) == ESP_OK) {
        size_t start = 0;
        while (start < 32 && value_bytes[start] == 0) start++;
        if (start == 32) start = 31;

        size_t actual_len = 32 - start;
        len_prefix = encode_rlp_length(actual_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], &value_bytes[start], actual_len);
        offset += actual_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // Field 6: data (use data_len since data is already uint8_t*)
    if (tx->data && tx->data_len > 0) {
        len_prefix = encode_rlp_length(tx->data_len, &rlp_data[offset], false);
        offset += len_prefix;
        memcpy(&rlp_data[offset], tx->data, tx->data_len);
        offset += tx->data_len;
    } else {
        rlp_data[offset++] = 0x80;
    }

    // EIP-155: Add chain_id, 0, 0 for replay protection
    field_len = encode_rlp_int(tx->chain_id, field_buffer);
    len_prefix = encode_rlp_length(field_len, &rlp_data[offset], false);
    offset += len_prefix;
    memcpy(&rlp_data[offset], field_buffer, field_len);
    offset += field_len;

    // Two empty values for EIP-155
    rlp_data[offset++] = 0x80;  // Empty r
    rlp_data[offset++] = 0x80;  // Empty s

    // Encode list length
    size_t fields_length = offset - fields_start;
    size_t actual_len_prefix = encode_rlp_length(fields_length, field_buffer, true);

    memmove(&rlp_data[list_length_offset + actual_len_prefix], &rlp_data[fields_start], fields_length);
    memcpy(&rlp_data[list_length_offset], field_buffer, actual_len_prefix);
    offset = list_length_offset + actual_len_prefix + fields_length;

    // Calculate Keccak-256 hash
    keccak_256(rlp_data, offset, tx_hash->hash);
    tx_hash->chain_id = tx->chain_id;

    ESP_LOGI(TAG, "EIP-155 transaction hash calculated (chain_id=%lu)", tx->chain_id);
    return ESP_OK;
}