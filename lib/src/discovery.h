#ifndef DISCOVERY_H
#define DISCOVERY_H

#include <sys/types.h>

typedef struct {
    pid_t pid;
    char process_name[256];
    char exe_path[512];
    int num_connections;
    int has_tcp;
    int has_udp;
} process_info;

typedef struct {
    process_info *processes;
    size_t count;
    size_t capacity;
} process_list;

process_list *get_network_processes(void);

void destroy_process_list(process_list *list);

#endif
