#include "discovery.h"
#include "ratelimit.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROGRAM_NAME "pidnl"
#define PROGRAM_USAGE                                                                              \
    "Usage: " PROGRAM_NAME " [OPTIONS] COMMAND [ARGS]...\n"                                        \
    "Commands:\n"                                                                                  \
    "  list                List processes with network connections\n"                              \
    "  limit               Limit bandwidth for a process\n"                                        \
    "  clean               Clean up all rate limits and cgroups\n"                                 \
    "\nOptions:\n"                                                                                 \
    "  -h, --help          Display this help message"

#define LIMIT_USAGE                                                                                \
    "Usage: " PROGRAM_NAME " limit set <pid> <upload_kbps> <download_kbps>\n"                      \
    "       " PROGRAM_NAME " limit unset <pid>\n\n"                                                \
    "Commands:\n"                                                                                  \
    "  set <pid> <upload> <download>    Limit bandwidth for a process\n"                           \
    "  unset <pid>                      Remove rate limit for a process\n\n"                       \
    "Examples:\n"                                                                                  \
    "  " PROGRAM_NAME " limit set 12345 1000 2000\n"                                               \
    "  " PROGRAM_NAME " limit unset 12345"

#define CLEAN_USAGE                                                                                \
    "Usage: " PROGRAM_NAME " clean [--yes]\n\n"                                                    \
    "Clean up all rate limits and cgroups created by " PROGRAM_NAME ".\n\n"                        \
    "Options:\n"                                                                                   \
    "  --yes, -y  Skip confirmation prompt\n\n"                                                    \
    "This will remove all rate limits from processes"

typedef void (*cmd_handler)(int argc, char *argv[]);

typedef struct {
    const char *name;
    const char *description;
    const char *usage;
    cmd_handler handler;
} command;

/* Forward declarations so the command table can reference them */
static void cmd_list(int argc, char *argv[]);
static void handle_limit(int argc, char *argv[]);
static void cmd_limit_set(int argc, char *argv[]);
static void cmd_limit_unset(int argc, char *argv[]);
static void cmd_clean(int argc, char *argv[]);

static uint32_t parse_rate(const char *arg) {
    if (strcmp(arg, "-1") == 0) {
        return RATELIMIT_UNLIMITED;
    }
    char *endptr;
    errno = 0;
    unsigned long ul = strtoul(arg, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || ul > UINT32_MAX) {
        fprintf(stderr, "%s: invalid rate: %s\n", PROGRAM_NAME, arg);
        exit(EXIT_FAILURE);
    }
    return (uint32_t)ul;
}

static pid_t parse_pid(const char *arg) {
    char *endptr;
    errno = 0;
    long pid_long = strtol(arg, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || pid_long <= 0) {
        fprintf(stderr, "%s: invalid PID: %s\n", PROGRAM_NAME, arg);
        exit(EXIT_FAILURE);
    }
    return (pid_t)pid_long;
}

static int has_help_flag(int argc, char *argv[]) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return 1;
        }
    }
    return 0;
}

static void format_limit(char *buf, size_t size, uint32_t kbps) {
    if (kbps == RATELIMIT_UNLIMITED) {
        snprintf(buf, size, "-");
        return;
    }
    snprintf(buf, size, "%u", kbps);
}

static void
print_process_list(process_list *list, uint32_t *upload_limits, uint32_t *download_limits) {
    printf(
        "%-8s %-20s %-10s %-10s %-12s %-12s %s\n",
        "PID",
        "NAME",
        "TCP",
        "UDP",
        "UP(KBPS)",
        "DOWN(KBPS)",
        "EXECUTABLE"
    );
    printf(
        "%-8s %-20s %-10s %-10s %-12s %-12s %s\n",
        "---",
        "----",
        "---",
        "---",
        "--------",
        "----------",
        "----------"
    );

    for (size_t i = 0; i < list->count; i++) {
        process_info *proc = &list->processes[i];
        char upload_str[20];
        char download_str[20];
        format_limit(upload_str, sizeof(upload_str), upload_limits[i]);
        format_limit(download_str, sizeof(download_str), download_limits[i]);
        printf(
            "%-8d %-20s %-10s %-10s %-12s %-12s %s\n",
            proc->pid,
            proc->process_name,
            proc->has_tcp ? "Yes" : "No",
            proc->has_udp ? "Yes" : "No",
            upload_str,
            download_str,
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

    uint32_t *upload_limits = calloc(list->count, sizeof(uint32_t));
    uint32_t *download_limits = calloc(list->count, sizeof(uint32_t));
    if (!upload_limits || !download_limits) {
        fprintf(stderr, "%s: failed to allocate memory\n", PROGRAM_NAME);
        destroy_process_list(list);
        free(upload_limits);
        free(download_limits);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < list->count; i++) {
        get_rate_limits_from_cgroup(list->processes[i].pid, &upload_limits[i], &download_limits[i]);
    }

    print_process_list(list, upload_limits, download_limits);
    free(upload_limits);
    free(download_limits);
    destroy_process_list(list);
}

static void cmd_limit_set(int argc, char *argv[]) {
    if (argc < 3) {
        printf("%s\n", LIMIT_USAGE);
        exit(EXIT_SUCCESS);
    }

    pid_t pid = parse_pid(argv[0]);
    uint32_t upload_kbps = parse_rate(argv[1]);
    uint32_t download_kbps = parse_rate(argv[2]);

    if (upload_kbps == RATELIMIT_UNLIMITED && download_kbps == RATELIMIT_UNLIMITED) {
        fprintf(
            stderr, "%s: Error: Cannot set both upload and download to unlimited\n", PROGRAM_NAME
        );
        exit(EXIT_FAILURE);
    }

    process_list *list = NULL;
    discovery_code disc_err = get_network_processes(&list);
    if (disc_err != DISCOVERY_OK) {
        fprintf(
            stderr,
            "%s: %s: %s\n",
            PROGRAM_NAME,
            "Failed to check process list",
            discovery_code_string(disc_err)
        );
        exit(EXIT_FAILURE);
    }

    int pid_found = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == pid) {
            pid_found = 1;
            break;
        }
    }

    if (!pid_found) {
        fprintf(
            stderr,
            "%s: PID %d not found in network process list. Run '%s list' to see available PIDs.\n",
            PROGRAM_NAME,
            pid,
            PROGRAM_NAME
        );
        destroy_process_list(list);
        exit(EXIT_FAILURE);
    }

    destroy_process_list(list);

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

    printf("Limiting PID %d to ", pid);
    if (upload_kbps == RATELIMIT_UNLIMITED) {
        printf("unlimited upload");
    } else {
        printf("%u kbps upload", upload_kbps);
    }
    if (download_kbps == RATELIMIT_UNLIMITED) {
        printf(", unlimited download");
    } else {
        printf(", %u kbps download", download_kbps);
    }
    printf("\n");
}

static void cmd_limit_unset(int argc, char *argv[]) {
    if (argc < 1) {
        printf("%s\n", LIMIT_USAGE);
        exit(EXIT_SUCCESS);
    }

    pid_t pid = parse_pid(argv[0]);

    ratelimit_code err = unregister_rate_limiter_by_pid(pid);
    if (err != RATELIMIT_OK) {
        fprintf(stderr, "%s: %s\n", PROGRAM_NAME, ratelimit_code_string(err));
        exit(EXIT_FAILURE);
    }

    printf("Removed rate limit for PID %d\n", pid);
}

static void handle_limit(int argc, char *argv[]) {
    if (has_help_flag(argc, argv)) {
        printf("%s\n", LIMIT_USAGE);
        exit(EXIT_SUCCESS);
    }

    if (argc < 1) {
        fprintf(stderr, "missing subcommand\n");
        fprintf(stderr, "Try '%s limit --help' for more information.\n", PROGRAM_NAME);
        exit(EXIT_FAILURE);
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

static void cmd_clean(int argc, char *argv[]) {
    int skip_confirmation = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
            skip_confirmation = 1;
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

    ratelimit_code err = ratelimit_cleanup_all();
    if (err != RATELIMIT_OK) {
        fprintf(stderr, "%s: %s\n", PROGRAM_NAME, ratelimit_code_string(err));
        exit(EXIT_FAILURE);
    }

    printf("Cleanup complete.\n");
}

static const command commands[] = {
    {"list", "List processes with network connections", PROGRAM_USAGE, cmd_list},
    {"limit", "Limit bandwidth for a process", LIMIT_USAGE, handle_limit},
    {"clean", "Clean up all rate limits", CLEAN_USAGE, cmd_clean},
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

    /* Handle --help/-h anywhere in the argument list first.
     * This makes all of these work:
     *   pidnl --help
     *   pidnl -h
     *   pidnl limit --help
     *   pidnl clean --help
     * All of them print usage and exit 0, no root required.
     */
    if (has_help_flag(argc, argv)) {
        int cmd_index = -1;
        for (int i = 1; i < argc; i++) {
            if (argv[i][0] != '-') {
                cmd_index = i;
                break;
            }
        }

        if (cmd_index < 0) {
            printf("%s\n", PROGRAM_USAGE);
            return EXIT_SUCCESS;
        }

        const command *cmd = find_command(argv[cmd_index]);
        if (cmd) {
            printf("%s\n", cmd->usage);
            return EXIT_SUCCESS;
        }

        fprintf(stderr, "%s: unknown command '%s'\n", PROGRAM_NAME, argv[cmd_index]);
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(stderr, "\nTry '%s --help' for more information.\n", PROGRAM_NAME);
        return EXIT_FAILURE;
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
    if (!cmd) {
        fprintf(stderr, "%s: unknown command '%s'\n", PROGRAM_NAME, argv[cmd_index]);
        fprintf(stderr, "\nAvailable commands:\n");
        print_command_list();
        fprintf(stderr, "\nTry '%s --help' for more information.\n", PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: this command requires root privileges\n", PROGRAM_NAME);
        return EXIT_FAILURE;
    }

    cmd->handler(argc - cmd_index - 1, argv + cmd_index + 1);
    return EXIT_SUCCESS;
}
