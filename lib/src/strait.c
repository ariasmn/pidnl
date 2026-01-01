#include "strait.h"

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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

// Send netlink request to get socket info
static int send_diag_request(int fd, int family, int protocol) {
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
    struct msghdr msg = {.msg_name = &nladdr,
                         .msg_namelen = sizeof(nladdr),
                         .msg_iov = &iov,
                         .msg_iovlen = 1};

    if (sendmsg(fd, &msg, 0) < 0) {
        perror("sendmsg");
        return -1;
    }

    return 0;
}

// Helper function to find PID by socket inode
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
            snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd/%s", pid,
                     fd_entry->d_name);

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

// Receive and parse netlink response
static int receive_diag_response(int fd, process_list_t *list, int is_tcp) {
    char buf[SOCKET_BUFFER_SIZE];
    struct sockaddr_nl nladdr;
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};

    while (1) {
        struct msghdr msg = {.msg_name = &nladdr,
                             .msg_namelen = sizeof(nladdr),
                             .msg_iov = &iov,
                             .msg_iovlen = 1};

        ssize_t ret = recvmsg(fd, &msg, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("recvmsg");
            return -1;
        }
        if (ret == 0) {
            return 0;
        }

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

                // Check if this socket belongs to a user process (uid >= 1000
                // or root)
                if (diag->idiag_uid == 0 || diag->idiag_uid >= 1000) {
                    // Quick scan of /proc to find PID owning this socket
                    pid_t pid = find_pid_by_inode(diag->idiag_inode);
                    if (pid > 0) {
                        add_process_list(list, pid, is_tcp);
                    }
                }
            }

            h = NLMSG_NEXT(h, ret);
        }
    }

    return 0;
}

process_list_t *get_network_processes(void) {
    int fd;
    process_list_t *list;

    // Create and bind Netlink socket
    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
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

    list = create_process_list();
    if (!list) {
        close(fd);
        return NULL;
    }

    // Query all TCP/UDP sockets
    if (send_diag_request(fd, AF_INET, IPPROTO_TCP) == 0) {
        receive_diag_response(fd, list, 1);
    }
    if (send_diag_request(fd, AF_INET6, IPPROTO_TCP) == 0) {
        receive_diag_response(fd, list, 1);
    }
    if (send_diag_request(fd, AF_INET, IPPROTO_UDP) == 0) {
        receive_diag_response(fd, list, 0);
    }
    if (send_diag_request(fd, AF_INET6, IPPROTO_UDP) == 0) {
        receive_diag_response(fd, list, 0);
    }

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
static int attach_bpf_programs(const char *cgroup_path, struct bpf_object **obj_out,
                                int *cgroup_fd_out) {
    struct bpf_object *obj;
    struct bpf_program *egress_prog, *ingress_prog;
    int egress_fd, ingress_fd;
    int cgroup_fd;
    int err;

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

    egress_fd = bpf_program__fd(egress_prog);
    ingress_fd = bpf_program__fd(ingress_prog);

    // Open cgroup
    cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup %s: %s\n", cgroup_path,
                strerror(errno));
        bpf_object__close(obj);
        return -1;
    }

    // Attach egress program
    err = bpf_prog_attach(egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0);
    if (err) {
        fprintf(stderr, "Failed to attach egress program: %s\n",
                strerror(errno));
        close(cgroup_fd);
        bpf_object__close(obj);
        return -1;
    }

    // Attach ingress program
    err = bpf_prog_attach(ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, 0);
    if (err) {
        fprintf(stderr, "Failed to attach ingress program: %s\n",
                strerror(errno));
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        close(cgroup_fd);
        bpf_object__close(obj);
        return -1;
    }

    *obj_out = obj;
    *cgroup_fd_out = cgroup_fd;

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
            fprintf(stderr, "Failed to open root cgroup: %s\n",
                    strerror(errno));
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

int limit_process_bandwidth(pid_t pid, rate_limit_config_t config,
                            rate_limiter_t **handle) {
    rate_limiter_t *limiter;
    char cgroup_path[512];
    int err;

    (void)config; // Config will be used when eBPF supports runtime limits

    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %d\n", pid);
        return -1;
    }

    if (!handle) {
        fprintf(stderr, "Handle pointer cannot be NULL\n");
        return -1;
    }

    limiter = malloc(sizeof(rate_limiter_t));
    if (!limiter) {
        fprintf(stderr, "Failed to allocate rate limiter\n");
        return -1;
    }

    memset(limiter, 0, sizeof(rate_limiter_t));
    limiter->pid = pid;

    // Create cgroup and move PID into it
    err = setup_cgroup(pid, cgroup_path, sizeof(cgroup_path));
    if (err) {
        fprintf(stderr, "Failed to setup cgroup\n");
        free(limiter);
        return -1;
    }

    snprintf(limiter->cgroup_path, sizeof(limiter->cgroup_path), "%s",
             cgroup_path);

    // Load and attach eBPF programs
    err = attach_bpf_programs(cgroup_path, &limiter->bpf_obj,
                              &limiter->cgroup_fd);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF programs\n");
        cleanup_cgroup(pid, cgroup_path);
        free(limiter);
        return -1;
    }

    *handle = limiter;
    return 0;
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
