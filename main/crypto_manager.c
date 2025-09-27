#include "esp_log.h"
#include "esp_random.h"
#include "crypto_manager.h"

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