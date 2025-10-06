#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include "esp_err.h"
#include "esp32_signer.h"  // For ecdsa_signature_t
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Transaction hash for signing
typedef struct {
    uint8_t hash[32];   // Keccak-256 hash of the transaction
    uint32_t chain_id;  // Ethereum chain ID for v calculation
} transaction_hash_t;

/**
 * @brief Initialize crypto manager with trezor-crypto
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_manager_init(void);

/**
 * @brief Generate a new secp256k1 private key
 * @param private_key Output buffer for 32-byte private key
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_generate_private_key(uint8_t private_key[32]);

/**
 * @brief Derive public key from private key
 * @param private_key Input 32-byte private key
 * @param public_key Output buffer for 64-byte uncompressed public key (32 bytes x + 32 bytes y)
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_get_public_key(const uint8_t private_key[32], uint8_t public_key[64]);

/**
 * @brief Get Ethereum address from public key
 * @param public_key Input 64-byte uncompressed public key
 * @param address Output buffer for 20-byte Ethereum address
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_get_ethereum_address(const uint8_t public_key[64], uint8_t address[20]);

/**
 * @brief Sign a transaction hash using secp256k1
 * @param private_key Input 32-byte private key
 * @param tx_hash Transaction hash structure with hash and chain_id
 * @param signature Output signature structure
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_sign_transaction(const uint8_t private_key[32],
                                 const transaction_hash_t *tx_hash,
                                 ecdsa_signature_t *signature);

/**
 * @brief Verify a signature against a hash and public key
 * @param public_key Input 64-byte uncompressed public key
 * @param hash Input 32-byte hash
 * @param signature Input signature structure
 * @return ESP_OK if valid, ESP_FAIL if invalid
 */
esp_err_t crypto_verify_signature(const uint8_t public_key[64],
                                 const uint8_t hash[32],
                                 const ecdsa_signature_t *signature);

/**
 * @brief Hash EIP-1559 transaction for signing
 * @param tx EIP-1559 transaction structure
 * @param tx_hash Output transaction hash structure
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_hash_eip1559_transaction(const eip1559_tx_t *tx, transaction_hash_t *tx_hash);

/**
 * @brief Hash EIP-155 transaction for signing
 * @param tx EIP-155 transaction structure
 * @param tx_hash Output transaction hash structure
 * @return ESP_OK on success, ESP_FAIL on failure
 */
esp_err_t crypto_hash_eip155_transaction(const eip155_tx_t *tx, transaction_hash_t *tx_hash);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_MANAGER_H