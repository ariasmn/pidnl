#include "discovery.h"
#include "ratelimit.h"
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROGRAM_NAME "strait"

static const char *program_usage =
    "Usage: " PROGRAM_NAME " [OPTIONS] COMMAND [ARGS]...\n"
    "Commands:\n"
    "  list                List processes with network connections\n"
    "  limit               Limit bandwidth for a process\n"
    "  help                Display this help message\n\n"
    "Options:\n"
    "  -h, --help          Display this help message\n";

typedef void (*cmd_handler_t)(int argc, char *argv[]);

typedef struct {
    const char *name;
    const char *description;
    cmd_handler_t handler;
} command_t;

static rate_limiter_t *g_limiter = NULL;

static void print_process_list(process_list_t *list) {
    printf(
        "%-8s %-20s %-10s %-10s %s\n", "PID", "NAME", "TCP", "UDP", "EXECUTABLE"
    );
    printf(
        "%-8s %-20s %-10s %-10s %s\n", "---", "----", "---", "---", "----------"
    );

    for (size_t i = 0; i < list->count; i++) {
        process_info_t *proc = &list->processes[i];
        printf(
            "%-8d %-20s %-10s %-10s %s\n", proc->pid, proc->process_name,
            proc->has_tcp ? "Yes" : "No", proc->has_udp ? "Yes" : "No",
            proc->exe_path[0] ? proc->exe_path : "(unknown)"
        );
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

static void cleanup_handler(int sig) {
    (void)sig;
    if (g_limiter) {
        printf("\nCleaning up rate limiter...\n");
        destroy_rate_limiter(g_limiter);
        g_limiter = NULL;
    }
    exit(0);
}

static void cmd_limit(int argc, char *argv[]) {
    int help_shown = 0;

    // Skip command name if present
    if (argc > 0 && strcmp(argv[0], "limit") == 0) {
        argv++;
        argc--;
    }

    // Check for --help
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            help_shown = 1;
            break;
        }
    }

    if (help_shown) {
        printf(
            "Usage: %s limit [OPTIONS] <pid> <upload_kbps> "
            "[<download_kbps>]\n\n"
            "Limit bandwidth for a process using eBPF and cgroups.\n\n"
            "Arguments:\n"
            "  pid                 Process ID to limit\n"
            "  upload_kbps         Upload rate limit in kbps (0 = unlimited)\n"
            "  download_kbps       Download rate limit in kbps (0 = "
            "unlimited)\n\n"
            "Options:\n"
            "  -h, --help          Display this help message\n\n"
            "Example:\n"
            "  %s limit 12345 1000 2000\n"
            "  (Limits process 12345 to 1000 kbps upload, 2000 kbps "
            "download)\n",
            PROGRAM_NAME, PROGRAM_NAME
        );
        exit(EXIT_SUCCESS);
    }

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "%s: missing or invalid arguments\n", PROGRAM_NAME);
        fprintf(
            stderr, "Try '%s limit --help' for more information.\n",
            PROGRAM_NAME
        );
        exit(EXIT_FAILURE);
    }

    pid_t pid = (pid_t)atoi(argv[0]);
    uint32_t upload_kbps = (uint32_t)atoi(argv[1]);
    uint32_t download_kbps = argc >= 3 ? (uint32_t)atoi(argv[2]) : 0;

    if (pid <= 0) {
        fprintf(stderr, "%s: invalid PID: %s\n", PROGRAM_NAME, argv[0]);
        exit(EXIT_FAILURE);
    }

    // Check for root
    if (geteuid() != 0) {
        fprintf(
            stderr, "%s: this command requires root privileges\n", PROGRAM_NAME
        );
        fprintf(stderr, "Try running with sudo:\n");
        fprintf(
            stderr, "  sudo %s limit <pid> <upload_kbps> [<download_kbps>]\n",
            PROGRAM_NAME
        );
        exit(EXIT_FAILURE);
    }

    rate_limit_config_t config = {
        .upload_kbps = upload_kbps, .download_kbps = download_kbps
    };

    printf("Limiting PID %d to %u kbps upload", pid, upload_kbps);
    if (download_kbps > 0) {
        printf(", %u kbps download", download_kbps);
    }
    printf("\n");

    g_limiter = limit_process_bandwidth(pid, config);
    if (!g_limiter) {
        fprintf(stderr, "%s: failed to limit bandwidth\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
    }

    // Setup signal handler for cleanup
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    printf("\nRate limiting active. Press Ctrl+C to exit.\n");
    printf("Note: The rate limit will be removed when this process exits.\n");

    // Keep running
    while (1) {
        sleep(1);
    }
}

static void cmd_help(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("%s", program_usage);
}

static const command_t commands[] = {
    {"list", "List processes with network connections", cmd_list},
    {"limit", "Limit bandwidth for a process", cmd_limit},
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
    // Check for global --help or -h before any command
    int global_help = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            // Show global help only if this -h/--help is at the beginning
            // and there's no command after it
            if (i == 1) {
                global_help = 1;
            }
            break;
        }
    }

    if (global_help) {
        printf("%s", program_usage);
        return EXIT_SUCCESS;
    }

    // Check if there's no command (no non-option argument)
    int cmd_index = -1;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            cmd_index = i;
            break;
        }
    }

    if (cmd_index < 0) {
        fprintf(stderr, "%s: missing command\n", PROGRAM_NAME);
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(
            stderr, "\nTry '%s --help' for more information.\n", PROGRAM_NAME
        );
        return EXIT_FAILURE;
    }

    // Dispatch to command
    const command_t *cmd = find_command(argv[cmd_index]);
    if (cmd) {
        cmd->handler(argc - cmd_index, argv + cmd_index);
    } else {
        fprintf(
            stderr, "%s: unknown command '%s'\n", PROGRAM_NAME, argv[cmd_index]
        );
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(
            stderr, "\nTry '%s --help' for more information.\n", PROGRAM_NAME
        );
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
