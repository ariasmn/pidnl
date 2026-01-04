#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uint32_t upload_kbps;
    uint32_t download_kbps;
} rate_limit_config_t;

typedef struct rate_limiter rate_limiter_t;

rate_limiter_t *limit_process_bandwidth(pid_t pid, rate_limit_config_t config);

void destroy_rate_limiter(rate_limiter_t *handle);

#endif
