#include "monitor.h"
#include "ratelimit.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

#define MAX_WATCHED_PIDS 1024
#define BUFFER_SIZE 256
#define DAEMON_TIMEOUT_MS 5000

struct pidfd_entry {
    pid_t pid;
    int pidfd;
    int active;
};

static struct pidfd_entry watched_pids[MAX_WATCHED_PIDS];
static int watched_count = 0;
static int monitor_socket = -1;
static int is_monitor_process = 0;
static int notify_parent_fd = -1;

// Find slot index for a watched PID, or -1 if not found
static int find_pid_slot(pid_t pid) {
    for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
        if (watched_pids[i].active && watched_pids[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

// Add PID to watch list, opening a pidfd for death detection
static int add_pid_to_watch(pid_t pid) {
    if (find_pid_slot(pid) >= 0) {
        return 0; // Already watching
    }

    int slot = -1;
    for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
        if (!watched_pids[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        return -1; // No slots
    }

    int pidfd = syscall(__NR_pidfd_open, pid, PIDFD_NONBLOCK);
    if (pidfd < 0) {
        unregister_rate_limiter_by_pid(pid);
        return -1;
    }

    watched_pids[slot].pid = pid;
    watched_pids[slot].pidfd = pidfd;
    watched_pids[slot].active = 1;
    watched_count++;

    return 0;
}

// Remove PID from watch list and close its pidfd
static int remove_pid_from_watch(pid_t pid) {
    int slot = find_pid_slot(pid);
    if (slot < 0) {
        return -1;
    }

    close(watched_pids[slot].pidfd);
    watched_pids[slot].active = 0;
    watched_pids[slot].pid = 0;
    watched_pids[slot].pidfd = -1;
    watched_count--;

    return 0;
}

// Connect to an already-running monitor, returns socket fd or -1
static int monitor_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MONITOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

// Main loop - runs in daemon process
// Big function but breaking into smaller ones is just missdirection IMHO.
static void monitor_run(void) {
    struct pollfd fds[MAX_WATCHED_PIDS + 2];
    char buffer[BUFFER_SIZE];

    is_monitor_process = 1;

    // Create unix socket
    struct sockaddr_un addr;
    struct stat st;
    if (stat(MONITOR_SOCKET_DIR, &st) < 0) {
        if (mkdir(MONITOR_SOCKET_DIR, 0755) < 0 && errno != EEXIST) {
            exit(1);
        }
    }
    unlink(MONITOR_SOCKET_PATH);

    monitor_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (monitor_socket < 0) {
        exit(1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MONITOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (bind(monitor_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(monitor_socket);
        exit(1);
    }
    if (listen(monitor_socket, 5) < 0) {
        close(monitor_socket);
        unlink(MONITOR_SOCKET_PATH);
        exit(1);
    }

    // Signal parent that socket is ready
    if (notify_parent_fd >= 0) {
        write(notify_parent_fd, "1", 1);
        close(notify_parent_fd);
        notify_parent_fd = -1;
    }

    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGPIPE, SIG_IGN);

    // Event loop
    while (1) {
        int nfds = 0;

        fds[nfds].fd = monitor_socket;
        fds[nfds].events = POLLIN;
        nfds++;

        for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
            if (watched_pids[i].active) {
                fds[nfds].fd = watched_pids[i].pidfd;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }

        int ret = poll(fds, nfds, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        // Handle new CLI connection
        if (fds[0].revents & POLLIN) {
            int client_fd = accept(monitor_socket, NULL, NULL);
            if (client_fd >= 0) {
                ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
                if (n > 0) {
                    buffer[n] = '\0';
                    char *nl = strchr(buffer, '\n');
                    if (nl)
                        *nl = '\0';

                    // Parse command
                    char response[BUFFER_SIZE];
                    pid_t cmd_pid;
                    if (strncmp(buffer, MONITOR_CMD_WATCH " ", strlen(MONITOR_CMD_WATCH " ")) ==
                        0) {
                        cmd_pid = atoi(buffer + strlen(MONITOR_CMD_WATCH " "));
                        if (cmd_pid <= 0) {
                            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Invalid PID");
                        } else if (add_pid_to_watch(cmd_pid) < 0) {
                            snprintf(
                                response, sizeof(response), MONITOR_CMD_ERROR " Failed to watch"
                            );
                        } else {
                            snprintf(response, sizeof(response), MONITOR_CMD_OK);
                        }
                    } else if (strncmp(
                                   buffer, MONITOR_CMD_UNWATCH " ", strlen(MONITOR_CMD_UNWATCH " ")
                               ) == 0) {
                        cmd_pid = atoi(buffer + strlen(MONITOR_CMD_UNWATCH " "));
                        if (cmd_pid <= 0) {
                            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Invalid PID");
                        } else if (remove_pid_from_watch(cmd_pid) < 0) {
                            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Not watching");
                        } else {
                            snprintf(response, sizeof(response), MONITOR_CMD_OK);
                        }
                    } else {
                        snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Unknown command");
                    }

                    write(client_fd, response, strlen(response));
                    write(client_fd, "\n", 1);
                }
                close(client_fd);
            }
        }

        // Handle PID deaths
        for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
            if (!watched_pids[i].active) {
                continue;
            }
            for (int j = 1; j < nfds; j++) {
                if (fds[j].fd == watched_pids[i].pidfd && (fds[j].revents & POLLIN)) {
                    pid_t pid = watched_pids[i].pid;
                    unregister_rate_limiter_by_pid(pid);
                    break;
                }
            }
        }

        // Exit when nothing left to watch
        if (watched_count == 0) {
            break;
        }
    }

    // Cleanup
    for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
        if (watched_pids[i].active) {
            close(watched_pids[i].pidfd);
        }
    }

    if (monitor_socket >= 0) {
        close(monitor_socket);
        unlink(MONITOR_SOCKET_PATH);
    }
}

// Start daemon if not running, returns socket fd
static int monitor_ensure_running(void) {
    int fd = monitor_connect();
    if (fd >= 0) {
        return fd;
    }

    // Pipe for synchronizing parent and daemon
    int ready_pipe[2];
    if (pipe(ready_pipe) < 0) {
        return -1;
    }

    // Double fork to create proper daemon
    pid_t session_child = fork();
    if (session_child < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return -1;
    }

    if (session_child == 0) {
        setsid();

        pid_t daemon = fork();
        if (daemon < 0) {
            _exit(1);
        }
        if (daemon > 0) {
            _exit(0);
        }

        close(ready_pipe[0]);
        notify_parent_fd = ready_pipe[1];

        monitor_run();
        _exit(0);
    }

    close(ready_pipe[1]);
    waitpid(session_child, NULL, 0);

    struct pollfd wait_daemon = {.fd = ready_pipe[0], .events = POLLIN};
    int ret = poll(&wait_daemon, 1, DAEMON_TIMEOUT_MS);
    close(ready_pipe[0]);

    if (ret <= 0) {
        return -1;
    }

    return monitor_connect();
}

// Send command to monitor, returns 0 on success
static int send_command(const char *cmd, pid_t pid) {
    if (is_monitor_process) {
        if (strcmp(cmd, MONITOR_CMD_WATCH) == 0) {
            return add_pid_to_watch(pid);
        } else if (strcmp(cmd, MONITOR_CMD_UNWATCH) == 0) {
            return remove_pid_from_watch(pid);
        }
        return -1;
    }

    int fd = monitor_ensure_running();
    if (fd < 0) {
        return -1;
    }

    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s %d\n", cmd, pid);

    if (write(fd, buffer, strlen(buffer)) < 0) {
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (n <= 0) {
        return -1;
    }

    buffer[n] = '\0';
    return strncmp(buffer, MONITOR_CMD_OK, strlen(MONITOR_CMD_OK)) == 0 ? 0 : -1;
}

int monitor_watch_pid(pid_t pid) { return send_command(MONITOR_CMD_WATCH, pid); }

int monitor_unwatch_pid(pid_t pid) { return send_command(MONITOR_CMD_UNWATCH, pid); }

int monitor_stop(void) {
    int fd = monitor_connect();
    if (fd < 0) {
        return 0;
    }

    close(fd);
    return 0;
}
