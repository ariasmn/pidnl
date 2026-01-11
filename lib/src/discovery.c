#include "discovery.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROC_PATH_MAX 64
#define SOCKET_LINK_MAX 64

/*
 * Netlink socket buffer size.
 * Page size varies by architecture (typically 4096 bytes).
 */
#define SOCKET_BUFFER_SIZE getpagesize()

typedef struct {
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 req;
} diag_request;

static process_list *create_process_list(void) {
    process_list *list = malloc(sizeof(process_list));
    if (!list)
        return NULL;

    list->capacity = 64;
    list->count = 0;
    list->processes = malloc(sizeof(process_info) * list->capacity);

    if (!list->processes) {
        free(list);
        return NULL;
    }

    return list;
}

static int add_process_list(process_list *list, pid_t pid, int is_tcp) {
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

    if (list->count >= list->capacity) {
        list->capacity *= 2;
        process_info *new_processes =
            realloc(list->processes, sizeof(process_info) * list->capacity);
        if (!new_processes) {
            return -1;
        }
        list->processes = new_processes;
    }

    process_info *proc = &list->processes[list->count];
    memset(proc, 0, sizeof(process_info));
    proc->pid = pid;
    proc->num_connections = 1;
    proc->has_tcp = is_tcp;
    proc->has_udp = !is_tcp;

    char path[PROC_PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(proc->process_name, sizeof(proc->process_name), f)) {
            size_t len = strlen(proc->process_name);
            if (len > 0 && proc->process_name[len - 1] == '\n') {
                proc->process_name[len - 1] = '\0';
            }
        }
        fclose(f);
    }

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, proc->exe_path, sizeof(proc->exe_path) - 1);
    if (len != -1) {
        proc->exe_path[len] = '\0';
    }

    list->count++;
    return 0;
}

static pid_t find_pid_by_inode(unsigned int inode) {
    char path[PROC_PATH_MAX];
    char link[SOCKET_LINK_MAX];

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
        return -1;

    struct dirent *proc_entry;
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        if (proc_entry->d_name[0] == '.')
            continue;

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

            char fd_path[PATH_MAX];
            snprintf(
                fd_path, sizeof(fd_path), "/proc/%ld/fd/%s", pid,
                fd_entry->d_name
            );

            ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
            if (len > 0) {
                link[len] = '\0';

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

static int query_sockets(int fd, int family, int protocol, process_list *list) {
    diag_request request;
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
                        add_process_list(list, pid, protocol == IPPROTO_TCP);
                    }
                }
            }
            h = NLMSG_NEXT(h, ret);
        }
    }
}

process_list *get_network_processes(void) {
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

    process_list *list = create_process_list();
    if (!list) {
        close(fd);
        return NULL;
    }

    query_sockets(fd, AF_INET, IPPROTO_TCP, list);
    query_sockets(fd, AF_INET6, IPPROTO_TCP, list);
    query_sockets(fd, AF_INET, IPPROTO_UDP, list);
    query_sockets(fd, AF_INET6, IPPROTO_UDP, list);

    close(fd);
    return list;
}

void destroy_process_list(process_list *list) {
    if (!list)
        return;
    free(list->processes);
    free(list);
}
