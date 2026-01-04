#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uint32_t upload_kbps;
    uint32_t download_kbps;
} rate_limit_config_t;

typedef struct {
    char cgroup_path[512];
    struct bpf_object *bpf_obj;
    int cgroup_fd;
} rate_limiter;

rate_limiter *limit_process_bandwidth(pid_t pid, rate_limit_config_t config);

void close_rate_limiter_handle(rate_limiter *handle);

int unregister_rate_limiter_by_pid(pid_t pid);

int cleanup_orphaned_cgroup(pid_t pid);

#endif
