#include "policy_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "POLICY_ENGINE";

// ERC-20 transfer function selector: transfer(address,uint256)
static const uint8_t ERC20_TRANSFER_SELECTOR[4] = {0xa9, 0x05, 0x9c, 0xbb};

esp_err_t policy_engine_init(void)
{
    ESP_LOGI(TAG, "Policy engine initialized");
    return ESP_OK;
}

esp_err_t validate_chain_id(uint32_t chain_id, const policy_t *policy)
{
    if (!policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // If no chains are whitelisted, allow any chain
    if (policy->num_chains == 0) {
        return ESP_OK;
    }

    // Check if chain_id is in whitelist
    for (uint8_t i = 0; i < policy->num_chains; i++) {
        if (policy->allowed_chains[i] == chain_id) {
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "Chain ID %lu not in whitelist", (unsigned long)chain_id);
    return ESP_ERR_NOT_ALLOWED;
}

esp_err_t validate_recipient(const uint8_t *to_address, const policy_t *policy)
{
    if (!to_address || !policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // If no recipients are whitelisted, allow any recipient
    if (policy->num_recipients == 0) {
        return ESP_OK;
    }

    // Check if to_address is in whitelist
    for (uint8_t i = 0; i < policy->num_recipients; i++) {
        if (memcmp(policy->recipient_whitelist[i], to_address, 20) == 0) {
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "Recipient address not in whitelist");
    return ESP_ERR_NOT_ALLOWED;
}

esp_err_t validate_erc20_token(const uint8_t *token_address, const policy_t *policy)
{
    if (!token_address || !policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // If no ERC-20 tokens are whitelisted, allow any token
    if (policy->num_erc20_tokens == 0) {
        return ESP_OK;
    }

    // Check if token_address is in whitelist
    for (uint8_t i = 0; i < policy->num_erc20_tokens; i++) {
        if (memcmp(policy->erc20_whitelist[i], token_address, 20) == 0) {
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "ERC-20 token address not in whitelist");
    return ESP_ERR_NOT_ALLOWED;
}

esp_err_t validate_contract_interaction(const uint8_t *contract_address, const policy_t *policy)
{
    if (!contract_address || !policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // If no contracts are whitelisted, allow any contract interaction
    if (policy->num_contracts == 0) {
        return ESP_OK;
    }

    // Check if contract_address is in whitelist
    for (uint8_t i = 0; i < policy->num_contracts; i++) {
        if (memcmp(policy->contract_whitelist[i], contract_address, 20) == 0) {
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "Contract address not in whitelist");
    return ESP_ERR_NOT_ALLOWED;
}

static esp_err_t determine_transaction_type_and_validate(const uint8_t *to_address,
                                                        const uint8_t *data,
                                                        size_t data_len,
                                                        const policy_t *policy)
{
    if (!to_address || !policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // Check if it's a native ETH transfer (no data or empty data)
    if (data_len == 0 || (data_len == 0 && data == NULL)) {
        return validate_recipient(to_address, policy);
    }

    // Check if it's an ERC-20 transfer (data starts with transfer function selector)
    if (data_len >= 4 && memcmp(data, ERC20_TRANSFER_SELECTOR, 4) == 0) {
        // It's an ERC-20 transfer, validate the token contract
        esp_err_t ret = validate_erc20_token(to_address, policy);
        if (ret != ESP_OK) {
            return ret;
        }

        // Extract recipient from ERC-20 transfer data and validate
        if (data_len >= 36) {  // 4 bytes selector + 32 bytes address (padded)
            uint8_t recipient[20];
            memcpy(recipient, data + 16, 20);  // Skip selector + 12 padding bytes
            return validate_recipient(recipient, policy);
        }
    }

    // For any other contract interaction, validate the contract
    return validate_contract_interaction(to_address, policy);
}

esp_err_t validate_eip1559_transaction(const eip1559_tx_t *tx, const policy_t *policy)
{
    if (!tx || !policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // Validate chain ID
    esp_err_t ret = validate_chain_id(tx->chain_id, policy);
    if (ret != ESP_OK) {
        return ret;
    }

    // Determine transaction type and validate accordingly
    return determine_transaction_type_and_validate(tx->to, tx->data, tx->data_len, policy);
}

esp_err_t validate_eip155_transaction(const eip155_tx_t *tx, const policy_t *policy)
{
    if (!tx || !policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // Validate chain ID
    esp_err_t ret = validate_chain_id(tx->chain_id, policy);
    if (ret != ESP_OK) {
        return ret;
    }

    // Determine transaction type and validate accordingly
    return determine_transaction_type_and_validate(tx->to, tx->data, tx->data_len, policy);
}

esp_err_t load_policy(policy_t *policy)
{
    if (!policy) {
        return ESP_ERR_INVALID_ARG;
    }

    // Try to load from storage
    esp_err_t ret = storage_get_policy(policy);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Policy loaded from storage");
        return ESP_OK;
    }

    // If no policy in storage, initialize to allow everything by default
    memset(policy, 0, sizeof(policy_t));
    ESP_LOGI(TAG, "No policy found in storage - using permissive defaults");
    return ESP_OK;
}

esp_err_t save_policy(const policy_t *policy)
{
    if (!policy) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret = storage_set_policy(policy);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save policy to storage: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "Policy saved to storage successfully");
    return ESP_OK;
}