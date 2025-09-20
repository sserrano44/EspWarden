#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t rate_limiter_init(void);

#ifdef __cplusplus
}
#endif

#endif // RATE_LIMITER_H