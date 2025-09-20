#ifndef DEVICE_MODE_H
#define DEVICE_MODE_H

#include "esp_err.h"
#include "esp32_signer.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t device_mode_init(void);
device_mode_t get_device_mode(void);
bool is_provisioning_mode(void);
bool is_signing_mode(void);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_MODE_H