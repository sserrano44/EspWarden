#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t storage_manager_init(void);

// Private key storage
esp_err_t storage_set_private_key(const uint8_t key[32]);
esp_err_t storage_get_private_key(uint8_t key[32]);
bool storage_has_private_key(void);

#ifdef __cplusplus
}
#endif

#endif // STORAGE_MANAGER_H