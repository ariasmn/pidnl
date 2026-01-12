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
        return -1;
    }

    return 0;
}

static ratelimit_code
setup_cgroup(pid_t pid, char *cgroup_path, size_t path_size) {
    int fd;
    char pid_str[PID_STR_MAX];
    int ret;

    if (ensure_parent_cgroup() != 0) {
        return RATELIMIT_MKDIR_CGROUP;
    }

    snprintf(cgroup_path, path_size, "%s/%d", CGROUP_PATH, pid);

    if (mkdir(cgroup_path, 0755) != 0 && errno != EEXIST) {
        return RATELIMIT_MKDIR_CGROUP;
    }

    char procs_path[PATH_MAX];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);

    fd = open(procs_path, O_WRONLY);
    if (fd < 0) {
        return RATELIMIT_OPEN_CGROUP;
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    ret = write(fd, pid_str, strlen(pid_str));
    close(fd);

    if (ret < 0) {
        return RATELIMIT_WRITE_PID;
    }

    return RATELIMIT_OK;
}

static ratelimit_code
attach_bpf_programs(rate_limiter *limiter, rate_limit_config config) {
    struct bpf_object *obj;
    struct bpf_program *egress_prog, *ingress_prog;
    struct bpf_map *rate_limits_map;
    int egress_fd, ingress_fd;
    int cgroup_fd;
    int err;
    __u64 upload_bps, download_bps;

    obj = bpf_object__open_file(BPF_OBJECT_PATH, NULL);
    if (libbpf_get_error(obj)) {
        return RATELIMIT_BPF_OPEN;
    }

    err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        return RATELIMIT_BPF_LOAD;
    }

    egress_prog = bpf_object__find_program_by_name(obj, "egress_rate_limit");
    ingress_prog = bpf_object__find_program_by_name(obj, "ingress_rate_limit");

    if (!egress_prog || !ingress_prog) {
        bpf_object__close(obj);
        return RATELIMIT_BPF_PROG_NOT_FOUND;
    }

    rate_limits_map = bpf_object__find_map_by_name(obj, "rate_limits");
    if (!rate_limits_map) {
        bpf_object__close(obj);
        return RATELIMIT_BPF_MAP_NOT_FOUND;
    }

    int rate_limits_map_fd = bpf_map__fd(rate_limits_map);

    upload_bps = (__u64)config.upload_kbps * 1000 / 8;
    download_bps = (__u64)config.download_kbps * 1000 / 8;

    err = bpf_map_update_elem(
        rate_limits_map_fd, &(unsigned int){DIRECTION_UPLOAD}, &upload_bps, 0
    );
    if (err) {
        err = bpf_map_update_elem(
            rate_limits_map_fd, &(unsigned int){DIRECTION_DOWNLOAD},
            &download_bps, 0
        );
        if (err) {
            bpf_object__close(obj);
            return RATELIMIT_BPF_MAP_UPDATE;
        }
    }

    err = bpf_map_update_elem(
        rate_limits_map_fd, &(unsigned int){DIRECTION_DOWNLOAD}, &download_bps,
        0
    );
    if (err) {
        bpf_object__close(obj);
        return RATELIMIT_BPF_MAP_UPDATE;
    }

    egress_fd = bpf_program__fd(egress_prog);
    ingress_fd = bpf_program__fd(ingress_prog);

    cgroup_fd = open(limiter->cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        bpf_object__close(obj);
        return RATELIMIT_OPEN_CGROUP;
    }

    err = bpf_prog_attach(egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0);
    if (err) {
        close(cgroup_fd);
        bpf_object__close(obj);
        return RATELIMIT_BPF_ATTACH;
    }

    err = bpf_prog_attach(ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, 0);
    if (err) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        close(cgroup_fd);
        bpf_object__close(obj);
        return RATELIMIT_BPF_ATTACH;
    }

    limiter->bpf_obj = obj;
    limiter->cgroup_fd = cgroup_fd;

    return RATELIMIT_OK;
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

    dir_fd = open(cgroup_path, O_RDONLY | __O_DIRECTORY);
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

ratelimit_code limit_process_bandwidth(pid_t pid, rate_limit_config config) {
    rate_limiter *limiter;
    ratelimit_code err;

    if (pid <= 0) {
        return RATELIMIT_INVALID_PID;
    }

    cleanup_orphaned_cgroup(pid);

    limiter = malloc(sizeof(rate_limiter));
    if (!limiter) {
        return RATELIMIT_ALLOC;
    }

    memset(limiter, 0, sizeof(rate_limiter));

    err = setup_cgroup(pid, limiter->cgroup_path, sizeof(limiter->cgroup_path));
    if (err != RATELIMIT_OK) {
        free(limiter);
        return RATELIMIT_SETUP_CGROUP;
    }

    err = attach_bpf_programs(limiter, config);
    if (err != RATELIMIT_OK) {
        cleanup_cgroup(pid, limiter->cgroup_path);
        free(limiter);
        return RATELIMIT_ATTACH_BPF;
    }

    close_rate_limiter_handle(limiter);
    return RATELIMIT_OK;
}

void close_rate_limiter_handle(rate_limiter *limiter) {
    if (!limiter)
        return;

    if (limiter->bpf_obj) {
        bpf_object__close(limiter->bpf_obj);
    }

    free(limiter);
}

ratelimit_code unregister_rate_limiter_by_pid(pid_t pid) {
    char cgroup_path[PATH_MAX];
    struct stat st;

    snprintf(cgroup_path, sizeof(cgroup_path), "%s/%d", CGROUP_PATH, pid);

    if (stat(cgroup_path, &st) != 0) {
        return RATELIMIT_CGROUP_NOT_FOUND;
    }

    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
        close(cgroup_fd);
    }

    cleanup_cgroup(pid, cgroup_path);

    return RATELIMIT_OK;
}

const char *ratelimit_code_string(ratelimit_code code) {
    switch (code) {
    case RATELIMIT_OK:
        return "Success";
    case RATELIMIT_INVALID_PID:
        return "Invalid PID";
    case RATELIMIT_ALLOC:
        return "Failed to allocate memory";
    case RATELIMIT_MKDIR_CGROUP:
        return "Failed to create cgroup directory";
    case RATELIMIT_OPEN_CGROUP:
        return "Failed to open cgroup file";
    case RATELIMIT_WRITE_PID:
        return "Failed to write PID to cgroup";
    case RATELIMIT_BPF_OPEN:
        return "Failed to open BPF object";
    case RATELIMIT_BPF_LOAD:
        return "Failed to load BPF object";
    case RATELIMIT_BPF_PROG_NOT_FOUND:
        return "Failed to find eBPF programs";
    case RATELIMIT_BPF_MAP_NOT_FOUND:
        return "Failed to find rate_limits map";
    case RATELIMIT_BPF_MAP_UPDATE:
        return "Failed to update rate limits map";
    case RATELIMIT_BPF_ATTACH:
        return "Failed to attach eBPF programs";
    case RATELIMIT_CGROUP_NOT_FOUND:
        return "No rate limit set for PID";
    case RATELIMIT_SETUP_CGROUP:
        return "Failed to setup cgroup";
    case RATELIMIT_ATTACH_BPF:
        return "Failed to attach eBPF programs";
    default:
        return "Unknown error";
    }
}
