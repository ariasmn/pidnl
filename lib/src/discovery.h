#ifndef DISCOVERY_H
#define DISCOVERY_H

#include <linux/limits.h>
#include <linux/taskstats.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    DISCOVERY_OK = 0,
    DISCOVERY_ALLOC,
    DISCOVERY_SOCKET,
    DISCOVERY_BIND,
    DISCOVERY_RECVMSG,
    DISCOVERY_NETLINK_MSG
} discovery_code;

typedef struct {
    pid_t pid;
    char process_name[TS_COMM_LEN];
    char exe_path[PATH_MAX];
    int num_connections;
    int has_tcp;
    int has_udp;
    uint64_t upload_limit;
    uint64_t download_limit;
} process_info;

typedef struct {
    process_info *processes;
    size_t count;
    size_t capacity;
} process_list;

discovery_code get_network_processes(process_list **out_list);

void destroy_process_list(process_list *list);

const char *discovery_code_string(discovery_code code);

#endif
