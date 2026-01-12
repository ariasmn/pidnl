#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <linux/limits.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    RATELIMIT_OK = 0,
    RATELIMIT_INVALID_PID,
    RATELIMIT_ALLOC,
    RATELIMIT_MKDIR_CGROUP,
    RATELIMIT_OPEN_CGROUP,
    RATELIMIT_WRITE_PID,
    RATELIMIT_BPF_OPEN,
    RATELIMIT_BPF_LOAD,
    RATELIMIT_BPF_PROG_NOT_FOUND,
    RATELIMIT_BPF_MAP_NOT_FOUND,
    RATELIMIT_BPF_MAP_UPDATE,
    RATELIMIT_BPF_ATTACH,
    RATELIMIT_CGROUP_NOT_FOUND,
    RATELIMIT_SETUP_CGROUP,
    RATELIMIT_ATTACH_BPF
} ratelimit_code;

typedef struct {
    uint32_t upload_kbps;
    uint32_t download_kbps;
} rate_limit_config;

typedef struct {
    char cgroup_path[PATH_MAX];
    struct bpf_object *bpf_obj;
    int cgroup_fd;
} rate_limiter;

ratelimit_code limit_process_bandwidth(pid_t pid, rate_limit_config config);

void close_rate_limiter_handle(rate_limiter *handle);

ratelimit_code unregister_rate_limiter_by_pid(pid_t pid);

const char *ratelimit_code_string(ratelimit_code code);

#endif
