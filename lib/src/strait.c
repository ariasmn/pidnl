#include "strait.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

// Netlink request message structure
// See https://docs.kernel.org/userspace-api/netlink/intro.html
typedef struct {
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 req;
} diag_request_t;

// Initializes an empty process list
static process_list_t *create_process_list(void) {
    process_list_t *list = malloc(sizeof(process_list_t));
    if (!list)
        return NULL;

    list->capacity = 64;
    list->count = 0;
    list->processes = malloc(sizeof(process_info_t) * list->capacity);

    if (!list->processes) {
        free(list);
        return NULL;
    }

    return list;
}

// Add or update process in list
static int add_process_list(process_list_t *list, pid_t pid, int is_tcp) {
    // Check if process already exists in the list
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == pid) {
            list->processes[i].num_connections++;
            if (is_tcp) {
                list->processes[i].has_tcp = 1;
            } else {
                list->processes[i].has_udp = 1;
            }
            return 0;
        }
    }

    // Expand array if needed
    if (list->count >= list->capacity) {
        list->capacity *= 2;
        process_info_t *new_processes =
            realloc(list->processes, sizeof(process_info_t) * list->capacity);
        if (!new_processes) {
            return -1;
        }
        list->processes = new_processes;
    }

    // Add new process
    process_info_t *proc = &list->processes[list->count];
    memset(proc, 0, sizeof(process_info_t));
    proc->pid = pid;
    proc->num_connections = 1;
    proc->has_tcp = is_tcp;
    proc->has_udp = !is_tcp;

    // Get process name from /proc/[pid]/comm
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(proc->process_name, sizeof(proc->process_name), f)) {
            // Remove trailing newline
            size_t len = strlen(proc->process_name);
            if (len > 0 && proc->process_name[len - 1] == '\n') {
                proc->process_name[len - 1] = '\0';
            }
        }
        fclose(f);
    }

    // Get executable path from /proc/[pid]/exe
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, proc->exe_path, sizeof(proc->exe_path) - 1);
    if (len != -1) {
        proc->exe_path[len] = '\0';
    }

    list->count++;
    return 0;
}

// Helper function to find PID by socket inode
// TODO: Revisit this. Slow and probably unsafe.
static pid_t find_pid_by_inode(unsigned int inode) {
    char path[64];
    char link[64];

    // Scan /proc for processes
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
        return -1;

    struct dirent *proc_entry;
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        // Skip non-numeric entries, meaning no processes related
        if (proc_entry->d_name[0] == '.')
            continue;

        // Check if it's a valid PID
        char *endptr;
        long pid = strtol(proc_entry->d_name, &endptr, 10);
        if (endptr == proc_entry->d_name)
            continue;

        snprintf(path, sizeof(path), "/proc/%ld/fd", pid);
        DIR *fd_dir = opendir(path);
        if (!fd_dir)
            continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            if (fd_entry->d_name[0] == '.')
                continue;

            char fd_path[512];
            snprintf(
                fd_path, sizeof(fd_path), "/proc/%ld/fd/%s", pid,
                fd_entry->d_name
            );

            ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
            if (len > 0) {
                link[len] = '\0';

                // Check if this is a socket with our inode
                unsigned int fd_inode;
                if (sscanf(link, "socket:[%u]", &fd_inode) == 1) {
                    if (fd_inode == inode) {
                        closedir(fd_dir);
                        closedir(proc_dir);
                        return (pid_t)pid;
                    }
                }
            }
        }

        closedir(fd_dir);
    }

    closedir(proc_dir);
    return -1;
}

static int
query_sockets(int fd, int family, int protocol, process_list_t *list) {
    // Send request
    diag_request_t request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = sizeof(request);
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.req.sdiag_family = family;
    request.req.sdiag_protocol = protocol;
    request.req.idiag_states = -1;
    request.req.idiag_ext = 0;

    struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
    struct iovec iov = {.iov_base = &request, .iov_len = sizeof(request)};
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    if (sendmsg(fd, &msg, 0) < 0) {
        perror("sendmsg");
        return -1;
    }

    // Receive response
    char buf[SOCKET_BUFFER_SIZE];
    while (1) {
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_iov = &iov;

        ssize_t ret = recvmsg(fd, &msg, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvmsg");
            return -1;
        }
        if (ret == 0)
            return 0;

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        while (NLMSG_OK(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(h);
                fprintf(stderr, "Netlink error: %s\n", strerror(-err->error));
                return -1;
            }
            if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
                struct inet_diag_msg *diag = NLMSG_DATA(h);
                if (diag->idiag_uid == 0 || diag->idiag_uid >= 1000) {
                    pid_t pid = find_pid_by_inode(diag->idiag_inode);
                    if (pid > 0) {
                        // Use protocol directly
                        add_process_list(list, pid, protocol == IPPROTO_TCP);
                    }
                }
            }
            h = NLMSG_NEXT(h, ret);
        }
    }
}

process_list_t *get_network_processes(void) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        perror("socket(AF_NETLINK)");
        return NULL;
    }

    struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
    if (bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        perror("bind(AF_NETLINK)");
        close(fd);
        return NULL;
    }

    process_list_t *list = create_process_list();
    if (!list) {
        close(fd);
        return NULL;
    }

    // Cleaner - no redundant parameter
    query_sockets(fd, AF_INET, IPPROTO_TCP, list);
    query_sockets(fd, AF_INET6, IPPROTO_TCP, list);
    query_sockets(fd, AF_INET, IPPROTO_UDP, list);
    query_sockets(fd, AF_INET6, IPPROTO_UDP, list);

    close(fd);
    return list;
}

void destroy_process_list(process_list_t *list) {
    if (!list)
        return;
    free(list->processes);
    free(list);
}

// ============ Rate Limiting using eBPF and cgroups ============

#define CGROUP_PATH "/sys/fs/cgroup/strait_rate_limit"

// Direction constants (must match eBPF program)
#define DIRECTION_UPLOAD 0
#define DIRECTION_DOWNLOAD 1

#ifdef INSTALLED
#define BPF_OBJECT_PATH "/usr/share/strait/ratelimit.bpf.o"
#else
#define BPF_OBJECT_PATH "lib/src/ratelimit.bpf.o"
#endif

struct rate_limiter {
    pid_t pid;
    char cgroup_path[512];
    struct bpf_object *bpf_obj;
    int cgroup_fd;
    int rate_limits_map_fd;
};

// Create cgroup and move PID into it
static int setup_cgroup(pid_t pid, char *cgroup_path, size_t path_size) {
    int fd;
    char pid_str[32];
    int ret;

    snprintf(cgroup_path, path_size, "%s_pid_%d", CGROUP_PATH, pid);

    // Create cgroup directory
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s 2>/dev/null || true", cgroup_path);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to create cgroup directory\n");
        return -1;
    }

    // Open cgroup.procs and write PID
    char procs_path[512];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);

    fd = open(procs_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", procs_path, strerror(errno));
        return -1;
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    ret = write(fd, pid_str, strlen(pid_str));
    close(fd);

    if (ret < 0) {
        fprintf(stderr, "Failed to write PID to cgroup: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// Load and attach eBPF programs to cgroup
// Fills the rate_limiter struct with bpf_obj, cgroup_fd, and rate_limits_map_fd
static int
attach_bpf_programs(rate_limiter_t *limiter, rate_limit_config_t config) {
    struct bpf_object *obj;
    struct bpf_program *egress_prog, *ingress_prog;
    struct bpf_map *rate_limits_map;
    int egress_fd, ingress_fd;
    int cgroup_fd;
    int err;
    __u64 upload_bps, download_bps;

    // Open and load BPF object
    obj = bpf_object__open_file(BPF_OBJECT_PATH, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    // Find programs
    egress_prog = bpf_object__find_program_by_name(obj, "egress_rate_limit");
    ingress_prog = bpf_object__find_program_by_name(obj, "ingress_rate_limit");

    if (!egress_prog || !ingress_prog) {
        fprintf(stderr, "Failed to find eBPF programs\n");
        bpf_object__close(obj);
        return -1;
    }

    // Find the rate_limits map
    rate_limits_map = bpf_object__find_map_by_name(obj, "rate_limits");
    if (!rate_limits_map) {
        fprintf(stderr, "Failed to find rate_limits map\n");
        bpf_object__close(obj);
        return -1;
    }

    limiter->rate_limits_map_fd = bpf_map__fd(rate_limits_map);

    // Initialize rate limits in the map (convert kbps to bps)
    upload_bps = (__u64)config.upload_kbps * 1000 / 8;
    download_bps = (__u64)config.download_kbps * 1000 / 8;

    // Direction UPLOAD
    err = bpf_map_update_elem(
        limiter->rate_limits_map_fd, &(unsigned int){DIRECTION_UPLOAD},
        &upload_bps, 0
    );
    if (err) {
        fprintf(stderr, "Failed to set upload limit in map: %d\n", err);
    }

    // Direction DOWNLOAD
    err = bpf_map_update_elem(
        limiter->rate_limits_map_fd, &(unsigned int){DIRECTION_DOWNLOAD},
        &download_bps, 0
    );
    if (err) {
        fprintf(stderr, "Failed to set download limit in map: %d\n", err);
    }

    egress_fd = bpf_program__fd(egress_prog);
    ingress_fd = bpf_program__fd(ingress_prog);

    // Open cgroup
    cgroup_fd = open(limiter->cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(
            stderr, "Failed to open cgroup %s: %s\n", limiter->cgroup_path,
            strerror(errno)
        );
        bpf_object__close(obj);
        return -1;
    }

    // Attach egress program
    err = bpf_prog_attach(egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0);
    if (err) {
        fprintf(
            stderr, "Failed to attach egress program: %s\n", strerror(errno)
        );
        close(cgroup_fd);
        bpf_object__close(obj);
        return -1;
    }

    // Attach ingress program
    err = bpf_prog_attach(ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, 0);
    if (err) {
        fprintf(
            stderr, "Failed to attach ingress program: %s\n", strerror(errno)
        );
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        close(cgroup_fd);
        bpf_object__close(obj);
        return -1;
    }

    limiter->bpf_obj = obj;
    limiter->cgroup_fd = cgroup_fd;

    return 0;
}

// Move PID back to root cgroup
static int cleanup_cgroup(pid_t pid, const char *cgroup_path) {
    int fd;
    char pid_str[32];

    // Open root cgroup.procs
    fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
    if (fd < 0) {
        // Try legacy path
        fd = open("/sys/fs/cgroup/tasks", O_WRONLY);
        if (fd < 0) {
            fprintf(
                stderr, "Failed to open root cgroup: %s\n", strerror(errno)
            );
            return -1;
        }
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    write(fd, pid_str, strlen(pid_str));
    close(fd);

    // Remove the cgroup directory
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rmdir %s 2>/dev/null || true", cgroup_path);
    system(cmd);

    return 0;
}

rate_limiter_t *limit_process_bandwidth(pid_t pid, rate_limit_config_t config) {
    rate_limiter_t *limiter;

    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %d\n", pid);
        return NULL;
    }

    limiter = malloc(sizeof(rate_limiter_t));
    if (!limiter) {
        fprintf(stderr, "Failed to allocate rate limiter\n");
        return NULL;
    }

    memset(limiter, 0, sizeof(rate_limiter_t));
    limiter->pid = pid;

    // Create cgroup and move PID into it
    if (setup_cgroup(pid, limiter->cgroup_path, sizeof(limiter->cgroup_path))) {
        fprintf(stderr, "Failed to setup cgroup\n");
        free(limiter);
        return NULL;
    }

    // Load and attach eBPF programs
    if (attach_bpf_programs(limiter, config)) {
        fprintf(stderr, "Failed to attach eBPF programs\n");
        cleanup_cgroup(pid, limiter->cgroup_path);
        free(limiter);
        return NULL;
    }

    return limiter;
}

void destroy_rate_limiter(rate_limiter_t *limiter) {
    if (!limiter)
        return;

    // Detach eBPF programs
    if (limiter->cgroup_fd >= 0) {
        bpf_prog_detach(limiter->cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(limiter->cgroup_fd, BPF_CGROUP_INET_INGRESS);
        close(limiter->cgroup_fd);
    }

    // Close BPF object
    if (limiter->bpf_obj) {
        bpf_object__close(limiter->bpf_obj);
    }

    // Move PID back to root cgroup and remove cgroup
    if (limiter->cgroup_path[0] != '\0') {
        cleanup_cgroup(limiter->pid, limiter->cgroup_path);
    }

    free(limiter);
}
