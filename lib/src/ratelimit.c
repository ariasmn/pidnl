#include "ratelimit.h"
#include "ratelimit_bpf.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libcgroup.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CGROUP_PARENT "strait"
#define CGROUP_MOUNT "/sys/fs/cgroup"

static const unsigned int DIRECTION_UPLOAD = 0;
static const unsigned int DIRECTION_DOWNLOAD = 1;

struct rate_limiter {
    struct cgroup *cg;
    struct ratelimit_bpf *skel;
    int cgroup_fd;
};

static int libcg_initialized = 0;

static ratelimit_code ensure_libcgroup_init(void) {
    if (libcg_initialized) {
        return RATELIMIT_OK;
    }
    if (cgroup_init() != 0) {
        return RATELIMIT_LIBCG_INIT;
    }
    libcg_initialized = 1;
    return RATELIMIT_OK;
}

static void get_cgroup_name(pid_t pid, char *buf, size_t size) {
    snprintf(buf, size, "%s/%d", CGROUP_PARENT, pid);
}

static int open_cgroup_fd(const char *cgroup_name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", CGROUP_MOUNT, cgroup_name);
    return open(path, O_RDONLY);
}

static ratelimit_code create_cgroup(const char *name, struct cgroup **out) {
    struct cgroup *cg;
    int ret;

    cg = cgroup_new_cgroup(name);
    if (!cg) {
        return RATELIMIT_LIBCG_CREATE;
    }

    ret = cgroup_create_cgroup(cg, 1);
    if (ret != 0 && !(ret == ECGOTHER && cgroup_get_last_errno() == EEXIST)) {
        cgroup_free(&cg);
        return RATELIMIT_LIBCG_CREATE;
    }

    if (out) {
        *out = cg;
    } else {
        cgroup_free(&cg);
    }
    return RATELIMIT_OK;
}

static void delete_cgroup(const char *name, int cgroup_fd) {
    struct cgroup *cg;

    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
        close(cgroup_fd);
    }

    cg = cgroup_new_cgroup(name);
    if (cg) {
        cgroup_delete_cgroup(cg, 1);
        cgroup_free(&cg);
    }
}

static ratelimit_code setup_cgroup(pid_t pid, struct cgroup **out_cg, int *out_fd) {
    char cgroup_name[PATH_MAX];
    struct cgroup *cg;
    ratelimit_code err;
    int fd;

    err = ensure_libcgroup_init();
    if (err != RATELIMIT_OK) {
        return err;
    }

    err = create_cgroup(CGROUP_PARENT, NULL);
    if (err != RATELIMIT_OK) {
        return err;
    }

    get_cgroup_name(pid, cgroup_name, sizeof(cgroup_name));

    err = create_cgroup(cgroup_name, &cg);
    if (err != RATELIMIT_OK) {
        return err;
    }

    if (cgroup_attach_task_pid(cg, pid) != 0) {
        cgroup_delete_cgroup(cg, 1);
        cgroup_free(&cg);
        return RATELIMIT_LIBCG_ATTACH;
    }

    fd = open_cgroup_fd(cgroup_name);
    if (fd < 0) {
        cgroup_delete_cgroup(cg, 1);
        cgroup_free(&cg);
        return RATELIMIT_OPEN_CGROUP;
    }

    *out_cg = cg;
    *out_fd = fd;
    return RATELIMIT_OK;
}

static ratelimit_code attach_bpf_programs(rate_limiter *limiter, rate_limit_config config) {
    struct ratelimit_bpf *skel;
    int map_fd, err;
    __u64 upload_bps, download_bps;

    skel = ratelimit_bpf__open();
    if (!skel) {
        return RATELIMIT_BPF_OPEN;
    }

    if (ratelimit_bpf__load(skel)) {
        ratelimit_bpf__destroy(skel);
        return RATELIMIT_BPF_LOAD;
    }

    map_fd = bpf_map__fd(skel->maps.rate_limits);
    upload_bps = (__u64)config.upload_kbps * 1000 / 8;
    download_bps = (__u64)config.download_kbps * 1000 / 8;

    err = bpf_map_update_elem(map_fd, &DIRECTION_UPLOAD, &upload_bps, 0);
    if (!err) {
        err = bpf_map_update_elem(map_fd, &DIRECTION_DOWNLOAD, &download_bps, 0);
    }
    if (err) {
        ratelimit_bpf__destroy(skel);
        return RATELIMIT_BPF_LOAD;
    }

    err = bpf_prog_attach(
        bpf_program__fd(skel->progs.egress_rate_limit),
        limiter->cgroup_fd,
        BPF_CGROUP_INET_EGRESS,
        0
    );
    if (err) {
        ratelimit_bpf__destroy(skel);
        return RATELIMIT_BPF_ATTACH;
    }

    err = bpf_prog_attach(
        bpf_program__fd(skel->progs.ingress_rate_limit),
        limiter->cgroup_fd,
        BPF_CGROUP_INET_INGRESS,
        0
    );
    if (err) {
        bpf_prog_detach(limiter->cgroup_fd, BPF_CGROUP_INET_EGRESS);
        ratelimit_bpf__destroy(skel);
        return RATELIMIT_BPF_ATTACH;
    }

    limiter->skel = skel;
    return RATELIMIT_OK;
}

ratelimit_code limit_process_bandwidth(pid_t pid, rate_limit_config config) {
    rate_limiter *limiter;
    char cgroup_name[PATH_MAX];
    ratelimit_code err;
    int old_fd;

    if (pid <= 0) {
        return RATELIMIT_INVALID_PID;
    }

    get_cgroup_name(pid, cgroup_name, sizeof(cgroup_name));
    old_fd = open_cgroup_fd(cgroup_name);
    if (old_fd >= 0) {
        delete_cgroup(cgroup_name, old_fd);
    }

    limiter = calloc(1, sizeof(rate_limiter));
    if (!limiter) {
        return RATELIMIT_ALLOC;
    }

    err = setup_cgroup(pid, &limiter->cg, &limiter->cgroup_fd);
    if (err != RATELIMIT_OK) {
        free(limiter);
        return err;
    }

    err = attach_bpf_programs(limiter, config);
    if (err != RATELIMIT_OK) {
        cgroup_delete_cgroup(limiter->cg, 1);
        cgroup_free(&limiter->cg);
        close(limiter->cgroup_fd);
        free(limiter);
        return err;
    }

    close_rate_limiter_handle(limiter);
    return RATELIMIT_OK;
}

void close_rate_limiter_handle(rate_limiter *limiter) {
    if (!limiter) {
        return;
    }
    if (limiter->skel) {
        ratelimit_bpf__destroy(limiter->skel);
    }
    if (limiter->cg) {
        cgroup_free(&limiter->cg);
    }
    free(limiter);
}

ratelimit_code unregister_rate_limiter_by_pid(pid_t pid) {
    char cgroup_name[PATH_MAX];
    int cgroup_fd;

    if (ensure_libcgroup_init() != RATELIMIT_OK) {
        return RATELIMIT_LIBCG_INIT;
    }

    get_cgroup_name(pid, cgroup_name, sizeof(cgroup_name));
    cgroup_fd = open_cgroup_fd(cgroup_name);
    if (cgroup_fd < 0) {
        return RATELIMIT_CGROUP_NOT_FOUND;
    }

    delete_cgroup(cgroup_name, cgroup_fd);
    return RATELIMIT_OK;
}

const char *ratelimit_code_string(ratelimit_code code) {
    switch (code) {
    case RATELIMIT_OK:
        return "Success";
    case RATELIMIT_INVALID_PID:
        return "Invalid PID";
    case RATELIMIT_ALLOC:
        return "Memory allocation failed";
    case RATELIMIT_OPEN_CGROUP:
        return "Failed to open cgroup";
    case RATELIMIT_BPF_OPEN:
        return "Failed to open BPF object";
    case RATELIMIT_BPF_LOAD:
        return "Failed to load BPF program";
    case RATELIMIT_BPF_ATTACH:
        return "Failed to attach BPF program";
    case RATELIMIT_CGROUP_NOT_FOUND:
        return "No rate limit set for PID";
    case RATELIMIT_LIBCG_INIT:
        return "Failed to initialize libcgroup";
    case RATELIMIT_LIBCG_CREATE:
        return "Failed to create cgroup";
    case RATELIMIT_LIBCG_ATTACH:
        return "Failed to attach process to cgroup";
    case RATELIMIT_LIBCG_DELETE:
        return "Failed to delete cgroup";
    default:
        return "Unknown error";
    }
}
