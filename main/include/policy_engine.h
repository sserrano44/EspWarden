#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "esp_err.h"
#include "esp32_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Policy engine initialization
esp_err_t policy_engine_init(void);

// Transaction validation functions
esp_err_t validate_chain_id(uint32_t chain_id, const policy_t *policy);
esp_err_t validate_recipient(const uint8_t *to_address, const policy_t *policy);
esp_err_t validate_erc20_token(const uint8_t *token_address, const policy_t *policy);
esp_err_t validate_contract_interaction(const uint8_t *contract_address, const policy_t *policy);

// Main transaction validation
esp_err_t validate_eip1559_transaction(const eip1559_tx_t *tx, const policy_t *policy);
esp_err_t validate_eip155_transaction(const eip155_tx_t *tx, const policy_t *policy);

// Policy management
esp_err_t load_policy(policy_t *policy);
esp_err_t save_policy(const policy_t *policy);

#ifdef __cplusplus
}
#endif

#endif // POLICY_ENGINE_H