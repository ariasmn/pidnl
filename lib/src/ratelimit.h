#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include <sys/types.h>

extern const uint32_t RATELIMIT_UNLIMITED;
extern const unsigned int DIRECTION_UPLOAD;
extern const unsigned int DIRECTION_DOWNLOAD;

typedef enum {
    RATELIMIT_OK = 0,
    RATELIMIT_INVALID_PID,
    RATELIMIT_ALLOC,
    RATELIMIT_OPEN_CGROUP,
    RATELIMIT_BPF_OPEN,
    RATELIMIT_BPF_LOAD,
    RATELIMIT_BPF_ATTACH,
    RATELIMIT_CGROUP_NOT_FOUND,
    RATELIMIT_LIBCG_INIT,
    RATELIMIT_LIBCG_CREATE,
    RATELIMIT_LIBCG_ATTACH,
    RATELIMIT_LIBCG_DELETE
} ratelimit_code;

typedef struct {
    uint32_t upload_kbps;
    uint32_t download_kbps;
} rate_limit_config;

typedef struct rate_limiter rate_limiter;

ratelimit_code ratelimit_init(void);

ratelimit_code limit_process_bandwidth(pid_t pid, rate_limit_config config);

void close_rate_limiter_handle(rate_limiter *handle);

ratelimit_code unregister_rate_limiter_by_pid(pid_t pid);

const char *ratelimit_code_string(ratelimit_code code);

ratelimit_code ratelimit_cleanup_all(void);

int get_rate_limits_from_cgroup(pid_t pid, uint64_t *upload, uint64_t *download);

#endif
