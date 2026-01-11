#include "ratelimit.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PID_STR_MAX 8

#ifndef BPF_OBJECT_PATH
#define BPF_OBJECT_PATH "lib/src/ratelimit.bpf.o"
#endif

#define CGROUP_PARENT "strait"
#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_PATH CGROUP_ROOT "/" CGROUP_PARENT

#define DIRECTION_UPLOAD 0
#define DIRECTION_DOWNLOAD 1

struct rate_limiter {
    char cgroup_path[PATH_MAX];
    struct bpf_object *bpf_obj;
    int cgroup_fd;
};

static int ensure_parent_cgroup() {
    struct stat st;

    if (stat(CGROUP_PATH, &st) == 0) {
        return 0;
    }

    if (mkdir(CGROUP_PATH, 0755) != 0 && errno != EEXIST) {
        fprintf(
            stderr, "Failed to create parent cgroup: %s\n", strerror(errno)
        );
        return -1;
    }

    return 0;
}

static int setup_cgroup(pid_t pid, char *cgroup_path, size_t path_size) {
    int fd;
    char pid_str[PID_STR_MAX];
    int ret;

    if (ensure_parent_cgroup() != 0) {
        return -1;
    }

    snprintf(cgroup_path, path_size, "%s/%d", CGROUP_PATH, pid);

    if (mkdir(cgroup_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create cgroup: %s\n", strerror(errno));
        return -1;
    }

    char procs_path[PATH_MAX];
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

static int
attach_bpf_programs(rate_limiter *limiter, rate_limit_config_t config) {
    struct bpf_object *obj;
    struct bpf_program *egress_prog, *ingress_prog;
    struct bpf_map *rate_limits_map;
    int egress_fd, ingress_fd;
    int cgroup_fd;
    int err;
    __u64 upload_bps, download_bps;

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

    egress_prog = bpf_object__find_program_by_name(obj, "egress_rate_limit");
    ingress_prog = bpf_object__find_program_by_name(obj, "ingress_rate_limit");

    if (!egress_prog || !ingress_prog) {
        fprintf(stderr, "Failed to find eBPF programs\n");
        bpf_object__close(obj);
        return -1;
    }

    rate_limits_map = bpf_object__find_map_by_name(obj, "rate_limits");
    if (!rate_limits_map) {
        fprintf(stderr, "Failed to find rate_limits map\n");
        bpf_object__close(obj);
        return -1;
    }

    int rate_limits_map_fd = bpf_map__fd(rate_limits_map);

    upload_bps = (__u64)config.upload_kbps * 1000 / 8;
    download_bps = (__u64)config.download_kbps * 1000 / 8;

    err = bpf_map_update_elem(
        rate_limits_map_fd, &(unsigned int){DIRECTION_UPLOAD}, &upload_bps, 0
    );
    if (err) {
        fprintf(stderr, "Failed to set upload limit in map: %d\n", err);
    }

    err = bpf_map_update_elem(
        rate_limits_map_fd, &(unsigned int){DIRECTION_DOWNLOAD}, &download_bps,
        0
    );
    if (err) {
        fprintf(stderr, "Failed to set download limit in map: %d\n", err);
    }

    egress_fd = bpf_program__fd(egress_prog);
    ingress_fd = bpf_program__fd(ingress_prog);

    cgroup_fd = open(limiter->cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(
            stderr, "Failed to open cgroup %s: %s\n", limiter->cgroup_path,
            strerror(errno)
        );
        bpf_object__close(obj);
        return -1;
    }

    err = bpf_prog_attach(egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0);
    if (err) {
        fprintf(
            stderr, "Failed to attach egress program: %s\n", strerror(errno)
        );
        close(cgroup_fd);
        bpf_object__close(obj);
        return -1;
    }

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

static int cleanup_cgroup(pid_t pid, const char *cgroup_path) {
    int fd;
    char pid_str[PID_STR_MAX];
    int dir_fd;
    DIR *d;
    struct dirent *entry;

    fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
    if (fd < 0) {
        return -1;
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    write(fd, pid_str, strlen(pid_str));
    close(fd);

    dir_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        d = fdopendir(dir_fd);
        if (d != NULL) {
            while ((entry = readdir(d)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) {
                    continue;
                }
                unlinkat(dir_fd, entry->d_name, 0);
            }
            closedir(d);
        }
        close(dir_fd);
    }
    rmdir(cgroup_path);

    return 0;
}

static int cleanup_orphaned_cgroup(pid_t pid) {
    char cgroup_path[PATH_MAX];
    struct stat st;

    snprintf(cgroup_path, sizeof(cgroup_path), "%s/%d", CGROUP_PATH, pid);

    if (stat(cgroup_path, &st) != 0) {
        return 0;
    }

    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
        close(cgroup_fd);
    }

    cleanup_cgroup(pid, cgroup_path);

    return 0;
}

rate_limiter *limit_process_bandwidth(pid_t pid, rate_limit_config_t config) {
    rate_limiter *limiter;

    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %d\n", pid);
        return NULL;
    }

    cleanup_orphaned_cgroup(pid);

    limiter = malloc(sizeof(rate_limiter));
    if (!limiter) {
        fprintf(stderr, "Failed to allocate rate limiter\n");
        return NULL;
    }

    memset(limiter, 0, sizeof(rate_limiter));

    if (setup_cgroup(pid, limiter->cgroup_path, sizeof(limiter->cgroup_path))) {
        fprintf(stderr, "Failed to setup cgroup\n");
        free(limiter);
        return NULL;
    }

    if (attach_bpf_programs(limiter, config)) {
        fprintf(stderr, "Failed to attach eBPF programs\n");
        cleanup_cgroup(pid, limiter->cgroup_path);
        free(limiter);
        return NULL;
    }

    return limiter;
}

void close_rate_limiter_handle(rate_limiter *limiter) {
    if (!limiter)
        return;

    if (limiter->bpf_obj) {
        bpf_object__close(limiter->bpf_obj);
    }

    free(limiter);
}

int unregister_rate_limiter_by_pid(pid_t pid) {
    char cgroup_path[PATH_MAX];
    struct stat st;

    snprintf(cgroup_path, sizeof(cgroup_path), "%s/%d", CGROUP_PATH, pid);

    if (stat(cgroup_path, &st) != 0) {
        return -1;
    }

    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
        close(cgroup_fd);
    }

    cleanup_cgroup(pid, cgroup_path);

    return 0;
}
