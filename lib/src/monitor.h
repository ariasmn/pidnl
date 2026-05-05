#ifndef MONITOR_H
#define MONITOR_H

#include <sys/types.h>

#define MONITOR_SOCKET_DIR "/run/strait"
#define MONITOR_SOCKET_PATH "/run/strait/monitor.sock"

enum {
    CMD_WATCH = 1,
    CMD_UNWATCH = 2,
    CMD_STOP = 3,
};

struct monitor_cmd {
    int cmd;
    pid_t pid;
};

typedef enum {
    MONITOR_OK = 0,
    MONITOR_SOCKET,
    MONITOR_CONNECT,
    MONITOR_BIND,
    MONITOR_LISTEN,
    MONITOR_PIPE,
    MONITOR_FORK,
    MONITOR_WRITE,
    MONITOR_READ,
    MONITOR_PIDFD,
    MONITOR_SLOTS,
    MONITOR_NOT_FOUND,
    MONITOR_TIMEOUT
} monitor_code;

monitor_code monitor_watch_pid(pid_t pid);
monitor_code monitor_unwatch_pid(pid_t pid);
monitor_code monitor_stop(void);

const char *monitor_code_string(monitor_code code);

#endif