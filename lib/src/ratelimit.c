#include "ratelimit.h"
#include "monitor.h"
#include "ratelimit_bpf.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libcgroup.h>
#include <linux/limits.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CGROUP_NAME "pidnl"

static const char PROC_MOUNTS[] = "/proc/mounts";
static const char CGROUP2_FS[] = "cgroup2";
static const char CGROUP_WALK_CONTROLLER[] = "cpu";

const uint32_t RATELIMIT_UNLIMITED = UINT32_MAX;
const unsigned int DIRECTION_UPLOAD = 0;
const unsigned int DIRECTION_DOWNLOAD = 1;

static const char *EGRESS_PROG_NAME = "egress_rl";
static const char *INGRESS_PROG_NAME = "ingress_rl";
static const char *RATE_LIMITS_MAP_NAME = "rate_limits";

struct rate_limiter {
    struct cgroup *cg;
    struct ratelimit_bpf *skel;
    int cgroup_fd;
};

static int open_cgroup_fd(const char *name) {
    char path[PATH_MAX];
    FILE *f;
    struct mntent *ent;

    f = setmntent(PROC_MOUNTS, "r");
    if (!f) {
        return -1;
    }

    while ((ent = getmntent(f)) != NULL) {
        if (strcmp(ent->mnt_type, CGROUP2_FS) == 0) {
            snprintf(path, sizeof(path), "%s/%s", ent->mnt_dir, name);
            endmntent(f);
            return open(path, O_RDONLY);
        }
    }

    endmntent(f);
    return -1;
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

    *out = cg;
    return RATELIMIT_OK;
}

static void delete_cgroup(struct cgroup *cg, int cgroup_fd) {
    if (cgroup_fd >= 0) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);
        close(cgroup_fd);
    }

    if (cg) {
        cgroup_delete_cgroup(cg, 1);
        cgroup_free(&cg);
    }
}

static ratelimit_code attach_bpf_programs(rate_limiter *limiter, rate_limit_config config) {
    struct ratelimit_bpf *skel;
    int map_fd, err;
    ratelimit_code ret;
    int upload_attached = 0;

    skel = ratelimit_bpf__open();
    if (!skel) {
        return RATELIMIT_BPF_OPEN;
    }

    if (ratelimit_bpf__load(skel)) {
        ratelimit_bpf__destroy(skel);
        return RATELIMIT_BPF_LOAD;
    }

    map_fd = bpf_map__fd(skel->maps.rate_limits);

    if (config.upload_kbps != RATELIMIT_UNLIMITED) {
        err = bpf_map_update_elem(map_fd, &DIRECTION_UPLOAD, &config.upload_kbps, 0);
        if (err) {
            ratelimit_bpf__destroy(skel);
            return RATELIMIT_BPF_LOAD;
        }

        ret = bpf_prog_attach(
            bpf_program__fd(skel->progs.egress_rl), limiter->cgroup_fd, BPF_CGROUP_INET_EGRESS, 0
        );
        if (ret) {
            ratelimit_bpf__destroy(skel);
            return RATELIMIT_BPF_ATTACH;
        }
        upload_attached = 1;
    }

    if (config.download_kbps != RATELIMIT_UNLIMITED) {
        err = bpf_map_update_elem(map_fd, &DIRECTION_DOWNLOAD, &config.download_kbps, 0);
        if (err) {
            if (upload_attached) {
                bpf_prog_detach(limiter->cgroup_fd, BPF_CGROUP_INET_EGRESS);
            }
            ratelimit_bpf__destroy(skel);
            return RATELIMIT_BPF_LOAD;
        }

        ret = bpf_prog_attach(
            bpf_program__fd(skel->progs.ingress_rl), limiter->cgroup_fd, BPF_CGROUP_INET_INGRESS, 0
        );
        if (ret) {
            if (upload_attached) {
                bpf_prog_detach(limiter->cgroup_fd, BPF_CGROUP_INET_EGRESS);
            }
            ratelimit_bpf__destroy(skel);
            return RATELIMIT_BPF_ATTACH;
        }
    }

    limiter->skel = skel;
    return RATELIMIT_OK;
}

static void build_cgroup_name(pid_t pid, char *buf, size_t size) {
    snprintf(buf, size, "%s/%d", CGROUP_NAME, pid);
}

ratelimit_code ratelimit_init(void) {
    if (cgroup_init() != 0) {
        return RATELIMIT_LIBCG_INIT;
    }
    return RATELIMIT_OK;
}

ratelimit_code limit_process_bandwidth(pid_t pid, rate_limit_config config) {
    rate_limiter *limiter;
    struct cgroup *parent = NULL, *child = NULL;
    ratelimit_code err;
    int cgroup_fd;
    char name[64];

    if (pid <= 0) {
        return RATELIMIT_INVALID_PID;
    }

    err = create_cgroup(CGROUP_NAME, &parent);
    if (err != RATELIMIT_OK) {
        return err;
    }

    build_cgroup_name(pid, name, sizeof(name));
    err = create_cgroup(name, &child);
    if (err != RATELIMIT_OK) {
        cgroup_free(&parent);
        return err;
    }

    if (cgroup_attach_task_pid(child, pid) != 0) {
        cgroup_delete_cgroup(child, 1);
        cgroup_free(&child);
        cgroup_free(&parent);
        return RATELIMIT_LIBCG_ATTACH;
    }

    cgroup_fd = open_cgroup_fd(name);
    if (cgroup_fd < 0) {
        cgroup_delete_cgroup(child, 1);
        cgroup_free(&child);
        cgroup_free(&parent);
        return RATELIMIT_OPEN_CGROUP;
    }

    limiter = calloc(1, sizeof(rate_limiter));
    if (!limiter) {
        delete_cgroup(child, cgroup_fd);
        cgroup_free(&parent);
        return RATELIMIT_ALLOC;
    }

    limiter->cg = child;
    limiter->cgroup_fd = cgroup_fd;

    // Detach any existing BPF programs before attaching new ones
    // This handles the case where limits are changed (e.g., from limited to unlimited)
    // TODO: Seems to works fine even if there's no BPF attached, I need to double check
    // if this is costly in terms of perfomance, although it doesn't seem like so.
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_INGRESS);

    err = attach_bpf_programs(limiter, config);
    if (err != RATELIMIT_OK) {
        delete_cgroup(limiter->cg, limiter->cgroup_fd);
        cgroup_free(&parent);
        free(limiter);
        return err;
    }

    cgroup_free(&parent);
    close_rate_limiter_handle(limiter);

    // TODO: Log warning if monitor registration fails
    monitor_watch_pid(pid);

    return RATELIMIT_OK;
}

void close_rate_limiter_handle(rate_limiter *limiter) {
    if (!limiter) {
        return;
    }
    if (limiter->cgroup_fd >= 0) {
        close(limiter->cgroup_fd);
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
    struct cgroup *cg = NULL;
    int cgroup_fd;
    char name[64];

    // TODO: Log warning if monitor unregistration fails
    monitor_unwatch_pid(pid);

    build_cgroup_name(pid, name, sizeof(name));

    cg = cgroup_new_cgroup(name);
    if (!cg) {
        return RATELIMIT_LIBCG_DELETE;
    }

    if (cgroup_get_cgroup(cg) != 0) {
        cgroup_free(&cg);
        return RATELIMIT_CGROUP_NOT_FOUND;
    }

    cgroup_fd = open_cgroup_fd(name);
    if (cgroup_fd < 0) {
        cgroup_free(&cg);
        return RATELIMIT_CGROUP_NOT_FOUND;
    }

    delete_cgroup(cg, cgroup_fd);
    return RATELIMIT_OK;
}

ratelimit_code ratelimit_cleanup_all(void) {
    struct cgroup *cg = cgroup_new_cgroup(CGROUP_NAME);
    if (!cg) {
        return RATELIMIT_OK;
    }
    if (cgroup_get_cgroup(cg) != 0) {
        cgroup_free(&cg);
        return RATELIMIT_OK;
    }

    // Using CGROUP_WALK_CONTROLLER since I don't care about the controller being
    // used, and I guess this one should always exist.
    void *handle = NULL;
    struct cgroup_file_info info;
    int base_level;
    int ret =
        cgroup_walk_tree_begin(CGROUP_WALK_CONTROLLER, CGROUP_NAME, 0, &handle, &info, &base_level);
    while (ret == 0) {
        if (info.type == CGROUP_FILE_TYPE_DIR && strcmp(info.path, "") != 0) {
            char name[64];
            char *endptr;
            errno = 0;
            long pid_long = strtol(info.path, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || pid_long <= 0) {
                ret = cgroup_walk_tree_next(0, &handle, &info, base_level);
                continue;
            }
            build_cgroup_name((pid_t)pid_long, name, sizeof(name));

            struct cgroup *child_cg = cgroup_new_cgroup(name);
            if (child_cg && cgroup_get_cgroup(child_cg) != 0) {
                cgroup_free(&child_cg);
            }
            if (child_cg) {
                int cgroup_fd = open_cgroup_fd(name);
                delete_cgroup(child_cg, cgroup_fd);
            }
        }
        ret = cgroup_walk_tree_next(0, &handle, &info, base_level);
    }
    cgroup_walk_tree_end(&handle);

    // We removed the children, now we delete the parent cgroup.
    // No need to get the fd since no BPF attached to parent.
    if (cgroup_delete_cgroup(cg, 1) != 0) {
        cgroup_free(&cg);
        return RATELIMIT_LIBCG_DELETE;
    }
    cgroup_free(&cg);

    monitor_stop();
    return RATELIMIT_OK;
}

static int read_limit_from_cgroup_progs(
    int cgroup_fd, enum bpf_attach_type attach_type, uint32_t *limit_kbps
) {
    *limit_kbps = 0;

    // We only attach one program per attach type (detach + no ALLOW_MULTI).
    __u32 prog_id = 0;
    LIBBPF_OPTS(bpf_prog_query_opts, opts);
    opts.prog_cnt = 1;
    opts.prog_ids = &prog_id;

    int ret = bpf_prog_query_opts(cgroup_fd, attach_type, &opts);
    if (ret < 0 || opts.prog_cnt == 0) {
        return -1;
    }

    const char *prog_name =
        (attach_type == BPF_CGROUP_INET_EGRESS) ? EGRESS_PROG_NAME : INGRESS_PROG_NAME;

    int prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) {
        return -1;
    }

    struct bpf_prog_info pinfo = {};
    __u32 map_ids[2]; // Same here, we should only have two maps at max.
    __u32 plen = sizeof(pinfo);
    pinfo.nr_map_ids = 2;
    pinfo.map_ids = (__u64)(unsigned long)map_ids;

    ret = bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen);
    if (ret < 0 || strncmp(pinfo.name, prog_name, BPF_OBJ_NAME_LEN) != 0 || pinfo.nr_map_ids == 0) {
        close(prog_fd);
        return -1;
    }

    for (__u32 i = 0; i < pinfo.nr_map_ids; i++) {
        int map_fd = bpf_map_get_fd_by_id(map_ids[i]);
        if (map_fd < 0) {
            continue;
        }

        struct bpf_map_info map_info = {};
        __u32 map_info_len = sizeof(map_info);
        if (bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len) == 0 &&
            strncmp(map_info.name, RATE_LIMITS_MAP_NAME, BPF_OBJ_NAME_LEN) == 0) {
            __u32 key =
                (attach_type == BPF_CGROUP_INET_EGRESS) ? DIRECTION_UPLOAD : DIRECTION_DOWNLOAD;
            __u32 value;
            if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
                *limit_kbps = value;
                close(map_fd);
                close(prog_fd);
                return 0;
            }
        }
        close(map_fd);
    }

    close(prog_fd);
    return -1;
}

int get_rate_limits_from_cgroup(pid_t pid, uint32_t *upload_kbps, uint32_t *download_kbps) {
    *upload_kbps = RATELIMIT_UNLIMITED;
    *download_kbps = RATELIMIT_UNLIMITED;

    if (pid <= 0) {
        return -1;
    }

    char name[64];
    build_cgroup_name(pid, name, sizeof(name));

    int cgroup_fd = open_cgroup_fd(name);
    if (cgroup_fd < 0) {
        return -1;
    }

    uint32_t kbps;
    if (read_limit_from_cgroup_progs(cgroup_fd, BPF_CGROUP_INET_EGRESS, &kbps) == 0) {
        *upload_kbps = kbps;
    }
    if (read_limit_from_cgroup_progs(cgroup_fd, BPF_CGROUP_INET_INGRESS, &kbps) == 0) {
        *download_kbps = kbps;
    }

    close(cgroup_fd);
    return 0;
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
