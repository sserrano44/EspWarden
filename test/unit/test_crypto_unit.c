/**
 * ESP32 Remote Signer - Crypto Manager Unit Tests
 * Tests for secp256k1 operations using Unity test framework
 */

#include "unity.h"
#include "crypto_manager.h"
#include "esp32_signer.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "CRYPTO_TEST";

// Test vectors for secp256k1
static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46,
    0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46,
    0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46,
    0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46
};

static const uint8_t TEST_MESSAGE_HASH[32] = {
    0x7c, 0x80, 0xd3, 0x88, 0x1f, 0x5b, 0x1d, 0xd9,
    0x5f, 0xe0, 0x0c, 0x47, 0x5f, 0x45, 0x0c, 0x5a,
    0x42, 0xa2, 0x52, 0xd5, 0x5e, 0xea, 0xa0, 0xe0,
    0xad, 0xb0, 0x47, 0xbe, 0x69, 0xba, 0xbe, 0x91
};

void setUp(void) {
    // Initialize crypto manager before each test
    TEST_ASSERT_EQUAL(ESP_OK, crypto_manager_init());
}

void tearDown(void) {
    // Cleanup after each test
}

void test_crypto_manager_init(void) {
    // Test initialization (already done in setUp)
    ESP_LOGI(TAG, "Testing crypto manager initialization");
    // Re-initialization should also succeed
    TEST_ASSERT_EQUAL(ESP_OK, crypto_manager_init());
}

void test_generate_private_key(void) {
    ESP_LOGI(TAG, "Testing private key generation");

    uint8_t private_key1[32] = {0};
    uint8_t private_key2[32] = {0};

    // Generate two keys
    TEST_ASSERT_EQUAL(ESP_OK, crypto_generate_private_key(private_key1));
    TEST_ASSERT_EQUAL(ESP_OK, crypto_generate_private_key(private_key2));

    // Keys should be different
    TEST_ASSERT_FALSE(memcmp(private_key1, private_key2, 32) == 0);

    // Keys should not be all zeros
    bool all_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (private_key1[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);

    ESP_LOGI(TAG, "Generated unique private keys successfully");
}

void test_derive_public_key(void) {
    ESP_LOGI(TAG, "Testing public key derivation");

    uint8_t public_key[64] = {0};

    // Derive public key from test private key
    TEST_ASSERT_EQUAL(ESP_OK, crypto_get_public_key(TEST_PRIVATE_KEY, public_key));

    // Public key should not be all zeros
    bool all_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (public_key[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);

    ESP_LOGI(TAG, "Derived public key successfully");
}

void test_ethereum_address_derivation(void) {
    ESP_LOGI(TAG, "Testing Ethereum address derivation");

    uint8_t public_key[64];
    uint8_t address[20] = {0};

    // First get public key
    TEST_ASSERT_EQUAL(ESP_OK, crypto_get_public_key(TEST_PRIVATE_KEY, public_key));

    // Derive Ethereum address
    TEST_ASSERT_EQUAL(ESP_OK, crypto_get_ethereum_address(public_key, address));

    // Address should not be all zeros
    bool all_zeros = true;
    for (int i = 0; i < 20; i++) {
        if (address[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);

    ESP_LOGI(TAG, "Derived Ethereum address: %02x%02x...%02x%02x",
             address[0], address[1], address[18], address[19]);
}

void test_transaction_signing(void) {
    ESP_LOGI(TAG, "Testing transaction signing");

    transaction_hash_t tx_hash = {
        .chain_id = 1
    };
    memcpy(tx_hash.hash, TEST_MESSAGE_HASH, 32);

    ecdsa_signature_t signature;

    // Sign the transaction
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &signature));

    // Signature components should not be all zeros
    bool r_zeros = true, s_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (signature.r[i] != 0) r_zeros = false;
        if (signature.s[i] != 0) s_zeros = false;
    }
    TEST_ASSERT_FALSE(r_zeros);
    TEST_ASSERT_FALSE(s_zeros);

    // V should be valid for chain_id = 1
    // v = recovery_id + 35 + 2 * chain_id
    // So v should be 37 or 38 for chain_id = 1
    TEST_ASSERT_TRUE(signature.v == 37 || signature.v == 38);

    ESP_LOGI(TAG, "Transaction signed successfully, v=%d", signature.v);
}

void test_signature_determinism(void) {
    ESP_LOGI(TAG, "Testing signature determinism");

    transaction_hash_t tx_hash = {
        .chain_id = 1
    };
    memcpy(tx_hash.hash, TEST_MESSAGE_HASH, 32);

    ecdsa_signature_t sig1, sig2;

    // Sign the same message twice
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &sig1));
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &sig2));

    // Signatures should be identical (RFC6979 deterministic signing)
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sig1.r, sig2.r, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sig1.s, sig2.s, 32);
    TEST_ASSERT_EQUAL(sig1.v, sig2.v);

    ESP_LOGI(TAG, "Signatures are deterministic as expected");
}

void test_signature_verification(void) {
    ESP_LOGI(TAG, "Testing signature verification");

    uint8_t public_key[64];
    transaction_hash_t tx_hash = {
        .chain_id = 1
    };
    memcpy(tx_hash.hash, TEST_MESSAGE_HASH, 32);

    ecdsa_signature_t signature;

    // Get public key and sign
    TEST_ASSERT_EQUAL(ESP_OK, crypto_get_public_key(TEST_PRIVATE_KEY, public_key));
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &signature));

    // Verify the signature
    TEST_ASSERT_EQUAL(ESP_OK, crypto_verify_signature(public_key, tx_hash.hash, &signature));

    // Modify signature and verify it fails
    signature.r[0] ^= 0xFF;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_verify_signature(public_key, tx_hash.hash, &signature));

    ESP_LOGI(TAG, "Signature verification working correctly");
}

void test_different_chain_ids(void) {
    ESP_LOGI(TAG, "Testing signatures with different chain IDs");

    transaction_hash_t tx_hash;
    memcpy(tx_hash.hash, TEST_MESSAGE_HASH, 32);

    ecdsa_signature_t sig_mainnet, sig_goerli, sig_legacy;

    // Test mainnet (chain_id = 1)
    tx_hash.chain_id = 1;
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &sig_mainnet));
    TEST_ASSERT_TRUE(sig_mainnet.v == 37 || sig_mainnet.v == 38);

    // Test Goerli (chain_id = 5)
    tx_hash.chain_id = 5;
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &sig_goerli));
    TEST_ASSERT_TRUE(sig_goerli.v == 45 || sig_goerli.v == 46);

    // Test legacy (chain_id = 0)
    tx_hash.chain_id = 0;
    TEST_ASSERT_EQUAL(ESP_OK, crypto_sign_transaction(TEST_PRIVATE_KEY, &tx_hash, &sig_legacy));
    TEST_ASSERT_TRUE(sig_legacy.v == 27 || sig_legacy.v == 28);

    ESP_LOGI(TAG, "Chain ID handling correct: mainnet v=%d, goerli v=%d, legacy v=%d",
             sig_mainnet.v, sig_goerli.v, sig_legacy.v);
}

void test_null_pointer_handling(void) {
    ESP_LOGI(TAG, "Testing NULL pointer handling");

    uint8_t buffer[64];
    transaction_hash_t tx_hash = {.chain_id = 1};
    ecdsa_signature_t signature;

    // Test NULL parameters
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_generate_private_key(NULL));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_get_public_key(NULL, buffer));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_get_public_key(buffer, NULL));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_get_ethereum_address(NULL, buffer));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_get_ethereum_address(buffer, NULL));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_sign_transaction(NULL, &tx_hash, &signature));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_sign_transaction(buffer, NULL, &signature));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_sign_transaction(buffer, &tx_hash, NULL));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_verify_signature(NULL, buffer, &signature));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_verify_signature(buffer, NULL, &signature));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, crypto_verify_signature(buffer, buffer, NULL));

    ESP_LOGI(TAG, "NULL pointer handling correct");
}

// Main test runner
void app_main(void) {
    ESP_LOGI(TAG, "Starting crypto unit tests");

    UNITY_BEGIN();

    RUN_TEST(test_crypto_manager_init);
    RUN_TEST(test_generate_private_key);
    RUN_TEST(test_derive_public_key);
    RUN_TEST(test_ethereum_address_derivation);
    RUN_TEST(test_transaction_signing);
    RUN_TEST(test_signature_determinism);
    RUN_TEST(test_signature_verification);
    RUN_TEST(test_different_chain_ids);
    RUN_TEST(test_null_pointer_handling);

    UNITY_END();

    ESP_LOGI(TAG, "Crypto unit tests completed");
}