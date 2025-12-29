#ifndef STRAIT_H
#define STRAIT_H

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
 * TCP connections and UDP sockets (listening or connected).
 *
 * @return A newly allocated process_list_t that must be freed with
 *         destroy_process_list(), or NULL on failure.
 */
process_list_t *get_network_processes(void);

/**
 * Free a process list and all its resources.
 *
 * @param list The process list to free, or NULL (no-op).
 */
void destroy_process_list(process_list_t *list);

#endif
