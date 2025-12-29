#include "strait.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROGRAM_NAME "strait"

static const char *program_usage =
    "Usage: " PROGRAM_NAME " [OPTIONS] COMMAND [ARGS]...\n"
    "List processes with network activity.\n\n"
    "Commands:\n"
    "  list                List processes with network connections\n"
    "  help                Display this help message\n\n"
    "Options:\n"
    "  -h, --help          Display this help message\n";

typedef void (*cmd_handler_t)(int argc, char *argv[]);

typedef struct {
    const char *name;
    const char *description;
    cmd_handler_t handler;
} command_t;

static void print_process_list(process_list_t *list) {
    printf("%-8s %-20s %-10s %-10s %s\n", "PID", "NAME", "TCP", "UDP",
           "EXECUTABLE");
    printf("%-8s %-20s %-10s %-10s %s\n", "---", "----", "---", "---",
           "----------");

    for (size_t i = 0; i < list->count; i++) {
        process_info_t *proc = &list->processes[i];
        printf("%-8d %-20s %-10s %-10s %s\n", proc->pid, proc->process_name,
               proc->has_tcp ? "Yes" : "No", proc->has_udp ? "Yes" : "No",
               proc->exe_path[0] ? proc->exe_path : "(unknown)");
    }
}

static void cmd_list(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    process_list_t *list = get_network_processes();
    if (!list) {
        fprintf(stderr, "Failed to discover processes\n");
        exit(EXIT_FAILURE);
    }

    print_process_list(list);
    destroy_process_list(list);
}

static void cmd_help(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("%s", program_usage);
}

static const command_t commands[] = {
    {"list", "List processes with network connections", cmd_list},
    {"help", "Display this help message", cmd_help},
};

static const size_t num_commands = sizeof(commands) / sizeof(commands[0]);

static const command_t *find_command(const char *name) {
    for (size_t i = 0; i < num_commands; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            return &commands[i];
        }
    }
    return NULL;
}

static void print_command_list(void) {
    for (size_t i = 0; i < num_commands; i++) {
        printf("  %-18s %s\n", commands[i].name, commands[i].description);
    }
}

int main(int argc, char *argv[]) {
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            printf("%s", program_usage);
            return EXIT_SUCCESS;
        default:
            fprintf(stderr, "Try '%s --help' for more information.\n",
                    PROGRAM_NAME);
            return EXIT_FAILURE;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        fprintf(stderr, "%s: missing command\n", PROGRAM_NAME);
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(stderr, "\nTry '%s --help' for more information.\n",
                PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    const command_t *cmd = find_command(argv[0]);
    if (cmd) {
        cmd->handler(argc, argv);
    } else {
        fprintf(stderr, "%s: unknown command '%s'\n", PROGRAM_NAME, argv[0]);
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(stderr, "\nTry '%s --help' for more information.\n",
                PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
