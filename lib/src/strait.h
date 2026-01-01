#ifndef STRAIT_H
#define STRAIT_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    char process_name[256];
    char exe_path[512];
    int num_connections;
    int has_tcp;
    int has_udp;
} process_info_t;

typedef struct {
    process_info_t *processes;
    size_t count;
    size_t capacity;
} process_list_t;

/**
 * Retrieve a list of processes with active network connections.
 *
 * Queries the kernel via netlink socket diagnostics to find all processes with
 * TCP or UDP connections (both IPv4 and IPv6). This includes both established
 * TCP concated process_list_t that must be freed with
 *         destroy_process_list(), or NULL on failure.
 */
process_list_t *get_network_processes(void);

/**
 * Free a process list and all its resources.
 *
 * @param list The process list to free, or NULL (no-op).
 */
void destroy_process_list(process_list_t *list);

/**
 * Rate limit configuration for limit_process_bandwidth()
 */
typedef struct {
    uint32_t upload_kbps;  // Upload limit in kilobits per second (0 = unlimited)
    uint32_t download_kbps; // Download limit in kilobits per second (0 = unlimited)
} rate_limit_config_t;

/**
 * Opaque handle for rate limiting (used for cleanup)
 */
typedef struct rate_limiter rate_limiter_t;

/**
 * Limit the bandwidth for a specific process using eBPF and cgroups.
 *
 * Creates a cgroup, moves the process into it, and attaches eBPF programs
 * for upload and download rate limiting. Returns a handle that must be
 * passed to destroy_rate_limiter() for cleanup.
 *
 * @param pid The process ID to limit
 * @param config Rate limit configuration
 * @param handle Pointer to receive the rate limiter handle
 * @return 0 on success, -1 on error
 */
int limit_process_bandwidth(pid_t pid, rate_limit_config_t config, rate_limiter_t **handle);

/**
 * Destroy a rate limiter and clean up resources.
 *
 * Detaches eBPF programs, moves the process back to the root cgroup,
 * and removes the rate limiting cgroup.
 *
 * @param handle The rate limiter handle from limit_process_bandwidth(), or NULL
 */
void destroy_rate_limiter(rate_limiter_t *handle);

#endif
