#include "monitor.h"
#include "ratelimit.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

#define MAX_WATCHED_PIDS 1024
#define DAEMON_TIMEOUT_MS 5000

struct pidfd_entry {
    pid_t pid;
    int pidfd;
    int active;
};

struct peer_cred {
    pid_t pid;
    uid_t uid;
    gid_t gid;
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
static monitor_code add_pid_to_watch(pid_t pid) {
    if (find_pid_slot(pid) >= 0) {
        return MONITOR_OK;
    }

    int slot = -1;
    for (int i = 0; i < MAX_WATCHED_PIDS; i++) {
        if (!watched_pids[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        return MONITOR_SLOTS;
    }

    int pidfd = syscall(__NR_pidfd_open, pid, PIDFD_NONBLOCK);
    if (pidfd < 0) {
        unregister_rate_limiter_by_pid(pid);
        return MONITOR_PIDFD;
    }

    watched_pids[slot].pid = pid;
    watched_pids[slot].pidfd = pidfd;
    watched_pids[slot].active = 1;
    watched_count++;

    return MONITOR_OK;
}

// Remove PID from watch list and close its pidfd
static monitor_code remove_pid_from_watch(pid_t pid) {
    int slot = find_pid_slot(pid);
    if (slot < 0) {
        return MONITOR_NOT_FOUND;
    }

    close(watched_pids[slot].pidfd);
    watched_pids[slot].active = 0;
    watched_pids[slot].pid = 0;
    watched_pids[slot].pidfd = -1;
    watched_count--;

    return MONITOR_OK;
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

    // Add timeout for the socket, in case the daemon disconnects the CLI doesn't hung.
    struct timeval tv = {
        .tv_sec = DAEMON_TIMEOUT_MS / 1000, .tv_usec = (DAEMON_TIMEOUT_MS % 1000) * 1000
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

// Main loop - runs in daemon process
// Big function but breaking into smaller ones is just missdirection IMHO.
static void monitor_run(void) {
    struct pollfd fds[MAX_WATCHED_PIDS + 2];

    is_monitor_process = 1;

    struct sockaddr_un addr;
    struct stat st;
    if (stat(MONITOR_SOCKET_DIR, &st) < 0) {
        if (mkdir(MONITOR_SOCKET_DIR, 0700) < 0 && errno != EEXIST) {
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
    int running = 1;
    while (running) {
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
            if (client_fd < 0) {
                continue;
            }

            struct peer_cred cred;
            socklen_t len = sizeof(cred);
            if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 || cred.uid != 0) {
                // Require root to prevent unprivileged users from sending commands
                close(client_fd);
                continue;
            }

            struct monitor_cmd msg;
            ssize_t n = read(client_fd, &msg, sizeof(msg));
            if (n != sizeof(msg)) {
                close(client_fd);
                continue;
            }

            int result = MONITOR_NOT_FOUND;
            if (msg.cmd == CMD_WATCH) {
                result = add_pid_to_watch(msg.pid);
            } else if (msg.cmd == CMD_UNWATCH) {
                result = remove_pid_from_watch(msg.pid);
            } else if (msg.cmd == CMD_STOP) {
                result = MONITOR_OK;
                running = 0;
            }

            write(client_fd, &result, sizeof(result));
            close(client_fd);
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

// Send command to monitor, returns monitor_code
static monitor_code send_command(int cmd, pid_t pid) {
    if (is_monitor_process) {
        if (cmd == CMD_WATCH)
            return add_pid_to_watch(pid);
        if (cmd == CMD_UNWATCH)
            return remove_pid_from_watch(pid);
        return MONITOR_NOT_FOUND;
    }

    int fd = monitor_ensure_running();
    if (fd < 0) {
        return MONITOR_CONNECT;
    }

    struct monitor_cmd msg = {.cmd = cmd, .pid = pid};
    if (write(fd, &msg, sizeof(msg)) < 0) {
        close(fd);
        return MONITOR_WRITE;
    }

    int result = -1;
    ssize_t n = read(fd, &result, sizeof(result));
    close(fd);

    if (n != sizeof(result)) {
        return MONITOR_TIMEOUT;
    }

    return (monitor_code)result;
}

monitor_code monitor_watch_pid(pid_t pid) { return send_command(CMD_WATCH, pid); }

monitor_code monitor_unwatch_pid(pid_t pid) { return send_command(CMD_UNWATCH, pid); }

monitor_code monitor_stop(void) {
    int fd = monitor_connect();
    if (fd < 0) {
        return MONITOR_OK;
    }

    struct monitor_cmd msg = {.cmd = CMD_STOP};
    if (write(fd, &msg, sizeof(msg)) < 0) {
        close(fd);
        return MONITOR_WRITE;
    }

    int result;
    ssize_t n = read(fd, &result, sizeof(result));
    close(fd);

    if (n != sizeof(result)) {
        return MONITOR_READ;
    }

    return (monitor_code)result;
}

const char *monitor_code_string(monitor_code code) {
    switch (code) {
    case MONITOR_OK:
        return "Success";
    case MONITOR_SOCKET:
        return "Failed to create socket";
    case MONITOR_CONNECT:
        return "Failed to connect to monitor daemon";
    case MONITOR_BIND:
        return "Failed to bind socket";
    case MONITOR_LISTEN:
        return "Failed to listen on socket";
    case MONITOR_PIPE:
        return "Failed to create pipe";
    case MONITOR_FORK:
        return "Failed to fork daemon process";
    case MONITOR_WRITE:
        return "Failed to write to socket";
    case MONITOR_READ:
        return "Failed to read from socket";
    case MONITOR_PIDFD:
        return "Failed to create pidfd";
    case MONITOR_SLOTS:
        return "No available slots for watching PIDs";
    case MONITOR_NOT_FOUND:
        return "PID not found in watch list";
    case MONITOR_TIMEOUT:
        return "Timeout waiting for daemon startup";
    default:
        return "Unknown error";
    }
}
