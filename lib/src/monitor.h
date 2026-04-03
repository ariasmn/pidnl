#ifndef MONITOR_H
#define MONITOR_H

#include <sys/types.h>

#define MONITOR_SOCKET_PATH "/run/strait/monitor.sock"
#define MONITOR_SOCKET_DIR "/run/strait"

enum {
    CMD_WATCH = 1,
    CMD_UNWATCH = 2,
};

struct monitor_cmd {
    int cmd;
    pid_t pid;
};

int monitor_watch_pid(pid_t pid);
int monitor_unwatch_pid(pid_t pid);
int monitor_stop(void);

#endif
