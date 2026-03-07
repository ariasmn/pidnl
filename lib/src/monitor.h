#ifndef MONITOR_H
#define MONITOR_H

#include <sys/types.h>

// Monitor socket path
#define MONITOR_SOCKET_PATH "/run/strait/monitor.sock"
#define MONITOR_SOCKET_DIR "/run/strait"

// Monitor protocol commands
#define MONITOR_CMD_WATCH "WATCH"
#define MONITOR_CMD_UNWATCH "UNWATCH"
#define MONITOR_CMD_OK "OK"
#define MONITOR_CMD_ERROR "ERROR"

// Connect to running monitor, returns socket fd or -1
int monitor_connect(void);

// Ensure monitor is running (connect or start), returns socket fd or -1
int monitor_ensure_running(void);

// Tell monitor to watch a PID (cleanup when it dies)
int monitor_watch_pid(pid_t pid);

// Tell monitor to stop watching a PID
int monitor_unwatch_pid(pid_t pid);

// Stop the monitor process (send shutdown signal)
int monitor_stop(void);

// Entry point for monitor process (called after fork)
void monitor_run(void);

#endif
