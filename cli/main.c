#include "discovery.h"
#include "ratelimit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROGRAM_NAME "strait"

static const char *program_usage = "Usage: " PROGRAM_NAME " [OPTIONS] COMMAND [ARGS]...\n"
                                   "Commands:\n"
                                   "  list                List processes with network connections\n"
                                   "  limit               Limit bandwidth for a process\n"
                                   "  clean               Clean up all rate limits and cgroups\n"
                                   "  help                Display this help message\n\n"
                                   "Options:\n"
                                   "  -h, --help          Display this help message";

static const char *limit_usage =
    "Usage: " PROGRAM_NAME " limit set <pid> <upload_kbps> <download_kbps>\n"
    "       " PROGRAM_NAME " limit unset <pid>\n\n"
    "Commands:\n"
    "  set <pid> <upload> <download>    Limit bandwidth for a process\n"
    "  unset <pid>                      Remove rate limit for a process\n\n"
    "Examples:\n"
    "  " PROGRAM_NAME " limit set 12345 1000 2000\n"
    "  " PROGRAM_NAME " limit unset 12345";

static const char *clean_usage =
    "Usage: " PROGRAM_NAME " clean [--yes]\n\n"
    "Clean up all rate limits and cgroups created by " PROGRAM_NAME ".\n\n"
    "Options:\n"
    "  --yes, -y  Skip confirmation prompt\n\n"
    "This will: remove all rate limits from processes\n";

    typedef void(*cmd_handler)(int argc, char *argv[]);

typedef struct {
    const char *name;
    const char *description;
    cmd_handler handler;
} command;

static void print_process_list(process_list *list) {
    printf("%-8s %-20s %-10s %-10s %s\n", "PID", "NAME", "TCP", "UDP", "EXECUTABLE");
    printf("%-8s %-20s %-10s %-10s %s\n", "---", "----", "---", "---", "----------");

    for (size_t i = 0; i < list->count; i++) {
        process_info *proc = &list->processes[i];
        printf(
            "%-8d %-20s %-10s %-10s %s\n",
            proc->pid,
            proc->process_name,
            proc->has_tcp ? "Yes" : "No",
            proc->has_udp ? "Yes" : "No",
            proc->exe_path[0] ? proc->exe_path : "(unknown)"
        );
    }
}

static void cmd_list(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    process_list *list;
    discovery_code err = get_network_processes(&list);
    if (err != DISCOVERY_OK) {
        fprintf(
            stderr,
            "%s: %s: %s\n",
            PROGRAM_NAME,
            "Failed to discover processes",
            discovery_code_string(err)
        );
        exit(EXIT_FAILURE);
    }

    print_process_list(list);
    destroy_process_list(list);
}

static void cmd_limit_set(int argc, char *argv[]) {
    int help_shown = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            help_shown = 1;
            break;
        }
    }

    if (help_shown || argc < 3) {
        printf("%s\n", limit_usage);
        exit(EXIT_SUCCESS);
    }

    pid_t pid = (pid_t)atoi(argv[0]);
    uint32_t upload_kbps = (uint32_t)atoi(argv[1]);
    uint32_t download_kbps = argc >= 3 ? (uint32_t)atoi(argv[2]) : 0;

    if (pid <= 0) {
        fprintf(stderr, "%s: invalid PID: %s\n", PROGRAM_NAME, argv[0]);
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: this command requires root privileges\n", PROGRAM_NAME);
        fprintf(stderr, "Try running with sudo:\n");
        fprintf(stderr, "  sudo %s limit set <pid> <upload> <download>\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
    }

    rate_limit_config config = {.upload_kbps = upload_kbps, .download_kbps = download_kbps};

    ratelimit_code err = limit_process_bandwidth(pid, config);
    if (err != RATELIMIT_OK) {
        fprintf(
            stderr,
            "%s: %s: %s\n",
            PROGRAM_NAME,
            "Failed to limit bandwidth",
            ratelimit_code_string(err)
        );
        exit(EXIT_FAILURE);
    }

    printf("Limiting PID %d to %u kbps upload", pid, upload_kbps);
    if (download_kbps > 0) {
        printf(", %u kbps download", download_kbps);
    }
    printf("\n");
}

static void cmd_limit_unset(int argc, char *argv[]) {
    int help_shown = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            help_shown = 1;
            break;
        }
    }

    if (help_shown || argc < 1) {
        printf("%s\n", limit_usage);
        exit(EXIT_SUCCESS);
    }

    pid_t pid = (pid_t)atoi(argv[0]);

    if (pid <= 0) {
        fprintf(stderr, "%s: invalid PID: %s\n", PROGRAM_NAME, argv[0]);
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: this command requires root privileges\n", PROGRAM_NAME);
        fprintf(stderr, "Try running with sudo:\n");
        fprintf(stderr, "  sudo %s limit unset <pid>\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
    }

    ratelimit_code err = unregister_rate_limiter_by_pid(pid);
    if (err != RATELIMIT_OK) {
        fprintf(stderr, "%s: %s\n", PROGRAM_NAME, ratelimit_code_string(err));
        exit(EXIT_FAILURE);
    }

    printf("Removed rate limit for PID %d\n", pid);
}

static void cmd_limit(int argc, char *argv[]) {
    int help_shown = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            help_shown = 1;
            break;
        }
    }

    if (help_shown) {
        printf("%s\n", limit_usage);
        exit(EXIT_SUCCESS);
    }

    if (argc < 1) {
        fprintf(stderr, "missing subcommand\n");
        fprintf(stderr, "Try '%s limit --help' for more information.\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[0], "limit") == 0) {
        argv++;
        argc--;
        if (argc < 1) {
            fprintf(stderr, "missing subcommand\n");
            fprintf(stderr, "Try '%s limit --help' for more information.\n", PROGRAM_NAME);
            exit(EXIT_FAILURE);
        }
    }

    if (strcmp(argv[0], "set") == 0) {
        cmd_limit_set(argc - 1, argv + 1);
    } else if (strcmp(argv[0], "unset") == 0) {
        cmd_limit_unset(argc - 1, argv + 1);
    } else {
        fprintf(stderr, "unknown subcommand: %s\n", argv[0]);
        fprintf(stderr, "Try '%s limit --help' for more information.\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
    }
}

static void cmd_help(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("%s\n", program_usage);
}

static void cmd_clean(int argc, char *argv[]) {
    int skip_confirmation = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
            skip_confirmation = 1;
            break;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("%s\n", clean_usage);
            exit(EXIT_SUCCESS);
        }
    }

    if (!skip_confirmation) {
        printf("This will remove all rate limits created by " PROGRAM_NAME ".\n");
        printf("Are you sure you want to continue? [y/N] ");

        int ch = getchar();
        if (ch != 'y' && ch != 'Y') {
            printf("Aborted.\n");
            exit(EXIT_SUCCESS);
        }
        while (getchar() != '\n')
            ;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: this command requires root privileges\n", PROGRAM_NAME);
        fprintf(stderr, "Try running with sudo:\n");
        fprintf(stderr, "  sudo %s clean\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
    }

    ratelimit_code err = ratelimit_cleanup_all();
    if (err != RATELIMIT_OK) {
        fprintf(stderr, "%s: %s\n", PROGRAM_NAME, ratelimit_code_string(err));
        exit(EXIT_FAILURE);
    }

    printf("Cleanup complete.\n");
}

static const command commands[] = {
    {"list", "List processes with network connections", cmd_list},
    {"limit", "Limit bandwidth for a process", cmd_limit},
    {"clean", "Clean up all rate limits", cmd_clean},
    {"help", "Display this help message", cmd_help},
};

static const size_t num_commands = sizeof(commands) / sizeof(commands[0]);

static const command *find_command(const char *name) {
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
    ratelimit_code err = ratelimit_init();
    if (err != RATELIMIT_OK) {
        fprintf(stderr, "%s: %s\n", PROGRAM_NAME, ratelimit_code_string(err));
        return EXIT_FAILURE;
    }

    int global_help = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            if (i == 1) {
                global_help = 1;
            }
            break;
        }
    }

    if (global_help) {
        printf("%s\n", program_usage);
        return EXIT_SUCCESS;
    }

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
        fprintf(stderr, "\nTry '%s --help' for more information.\n", PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    const command *cmd = find_command(argv[cmd_index]);
    if (cmd) {
        cmd->handler(argc - cmd_index, argv + cmd_index);
    } else {
        fprintf(stderr, "%s: unknown command '%s'\n", PROGRAM_NAME, argv[cmd_index]);
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(stderr, "\nTry '%s --help' for more information.\n", PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
