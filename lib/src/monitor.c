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
#define MAX_EVENTS 64
#define BUFFER_SIZE 256

struct pidfd_entry {
    pid_t pid;
    int pidfd;
    int active;
};

static struct pidfd_entry watched_pids[MAX_WATCHED_PIDS];
static int watched_count = 0;
static int monitor_socket = -1;
static int is_monitor_process = 0;
static int ready_fd = -1;

static int pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(__NR_pidfd_open, pid, flags);
}

static int find_pid_slot(pid_t pid) {
    for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
        if (watched_pids[i].active && watched_pids[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

static int find_empty_slot(void) {
    for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
        if (!watched_pids[i].active) {
            return i;
        }
    }
    return -1;
}

static int add_pid_to_watch(pid_t pid) {
    if (find_pid_slot(pid) >= 0) {
        return 0; // Already watching
    }

    int slot = find_empty_slot();
    if (slot < 0) {
        return -1; // No slots available
    }

    int pidfd = pidfd_open(pid, PIDFD_NONBLOCK);
    if (pidfd < 0) {
        // Process might already be dead, try cleanup directly
        unregister_rate_limiter_by_pid(pid);
        return -1;
    }

    watched_pids[slot].pid = pid;
    watched_pids[slot].pidfd = pidfd;
    watched_pids[slot].active = 1;
    watched_count++;

    return 0;
}

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

static void cleanup_pid_slot(int slot) {
    if (slot < 0 || slot >= MAX_WATCHED_PIDS || !watched_pids[slot].active) {
        return;
    }

    pid_t pid = watched_pids[slot].pid;

    unregister_rate_limiter_by_pid(pid);
}

static int create_monitor_socket(void) {
    struct sockaddr_un addr;
    int fd;

    // Ensure directory exists
    struct stat st;
    if (stat(MONITOR_SOCKET_DIR, &st) < 0) {
        if (mkdir(MONITOR_SOCKET_DIR, 0755) < 0 && errno != EEXIST) {
            perror("mkdir");
            return -1;
        }
    }

    // Remove stale socket if exists
    unlink(MONITOR_SOCKET_PATH);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MONITOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        perror("listen");
        close(fd);
        unlink(MONITOR_SOCKET_PATH);
        return -1;
    }

    return fd;
}

static void handle_client_command(int client_fd, const char *cmd) {
    char response[BUFFER_SIZE];
    pid_t pid;

    if (strncmp(cmd, MONITOR_CMD_WATCH " ", strlen(MONITOR_CMD_WATCH " ")) == 0) {
        pid = atoi(cmd + strlen(MONITOR_CMD_WATCH " "));
        if (pid <= 0) {
            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Invalid PID");
        } else if (add_pid_to_watch(pid) < 0) {
            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Failed to watch PID");
        } else {
            snprintf(response, sizeof(response), MONITOR_CMD_OK);
        }
    } else if (strncmp(cmd, MONITOR_CMD_UNWATCH " ", strlen(MONITOR_CMD_UNWATCH " ")) == 0) {
        pid = atoi(cmd + strlen(MONITOR_CMD_UNWATCH " "));
        if (pid <= 0) {
            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Invalid PID");
        } else if (remove_pid_from_watch(pid) < 0) {
            snprintf(response, sizeof(response), MONITOR_CMD_ERROR " PID not watched");
        } else {
            snprintf(response, sizeof(response), MONITOR_CMD_OK);
        }
    } else {
        snprintf(response, sizeof(response), MONITOR_CMD_ERROR " Unknown command");
    }

    write(client_fd, response, strlen(response));
    write(client_fd, "\n", 1);
}

void monitor_run(void) {
    struct pollfd fds[MAX_WATCHED_PIDS + 2]; // +2 for socket and signal handling
    char buffer[BUFFER_SIZE];
    int running = 1;

    is_monitor_process = 1;

    // Create socket
    monitor_socket = create_monitor_socket();
    if (monitor_socket < 0) {
        exit(1);
    }

    // Signal parent that we're ready
    if (ready_fd >= 0) {
        write(ready_fd, "1", 1);
        close(ready_fd);
        ready_fd = -1;
    }

    // Set up signal handling
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGPIPE, SIG_IGN);

    while (running) {
        // Build poll array
        int nfds = 0;

        // Add monitor socket
        fds[nfds].fd = monitor_socket;
        fds[nfds].events = POLLIN;
        nfds++;

        // Add all active pidfds
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
            perror("poll");
            break;
        }

        // Check for new connections
        if (fds[0].revents & POLLIN) {
            int client_fd = accept(monitor_socket, NULL, NULL);
            if (client_fd >= 0) {
                ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
                if (n > 0) {
                    buffer[n] = '\0';
                    // Remove trailing newline
                    char *nl = strchr(buffer, '\n');
                    if (nl)
                        *nl = '\0';
                    handle_client_command(client_fd, buffer);
                }
                close(client_fd);
            }
        }

        // Check for PID deaths
        for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
            if (watched_pids[i].active) {
                // Find the corresponding fd in poll array
                for (int j = 1; j < nfds; j++) {
                    if (fds[j].fd == watched_pids[i].pidfd && (fds[j].revents & POLLIN)) {
                        // PID died
                        cleanup_pid_slot(i);
                        break;
                    }
                }
            }
        }

        // Exit if no more PIDs to watch
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

int monitor_connect(void) {
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MONITOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int monitor_ensure_running(void) {
    int fd = monitor_connect();
    if (fd >= 0) {
        return fd;
    }

    // Monitor not running, start it
    // Create pipe for synchronization
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        // Child process - become monitor
        close(pipefd[0]);
        ready_fd = pipefd[1];
        setsid();

        monitor_run();
        exit(0);
    }

    // Parent - close write end and wait for child to signal readiness
    close(pipefd[1]);

    // Use poll with timeout (5 seconds) to wait for readiness signal
    struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
    int ret = poll(&pfd, 1, 5000);
    close(pipefd[0]);

    if (ret <= 0) {
        // Timeout or error - child didn't signal in time
        return -1;
    }

    // Child is ready, try to connect
    fd = monitor_connect();
    return fd;
}

static int send_command(const char *cmd, pid_t pid) {
    // If we're the monitor process, call internal functions directly
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

    // Read response
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (n <= 0) {
        return -1;
    }

    buffer[n] = '\0';

    // Check if response starts with OK
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
