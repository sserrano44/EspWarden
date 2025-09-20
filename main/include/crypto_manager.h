#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t crypto_manager_init(void);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_MANAGER_H