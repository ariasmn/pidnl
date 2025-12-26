#include "strait.h"
#include <stdio.h>

int main(void) {
    printf("=== Discovering processes with network activity ===\n\n");

    process_list_t *list = get_network_processes();
    if (!list) {
        fprintf(stderr, "Failed to discover processes\n");
        return 1;
    }

    printf("\nFound %zu processes with network activity:\n\n", list->count);
    printf("%-8s %-20s %-10s %-10s %s\n",
           "PID", "NAME", "TCP", "UDP", "EXECUTABLE");
    printf("%-8s %-20s %-10s %-10s %s\n",
           "---", "----", "---", "---", "----------");

    for (size_t i = 0; i < list->count; i++) {
        process_info_t *proc = &list->processes[i];
        printf("%-8d %-20s %-10s %-10s %s\n",
               proc->pid,
               proc->process_name,
               proc->has_tcp ? "Yes" : "No",
               proc->has_udp ? "Yes" : "No",
               proc->exe_path[0] ? proc->exe_path : "(unknown)");
    }

    printf("\nTotal: %zu processes\n", list->count);

    destroy_process_list(list);
    return 0;
}
