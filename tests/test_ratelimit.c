#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/limits.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <libcgroup.h>
#include <libcgroup/iterators.h>

#include "ratelimit.h"

int __wrap_cgroup_init(void) { return 0; }

void *__wrap_cgroup_new_cgroup(const char *name) {
    check_expected_ptr(name);
    return (void *)mock();
}

int __wrap_cgroup_create_cgroup(void *cg, int ignore_ownership) {
    (void)cg;
    (void)ignore_ownership;
    return (int)mock();
}

int __wrap_cgroup_delete_cgroup(void *cg, int ignore_ownership) {
    (void)cg;
    (void)ignore_ownership;
    return (int)mock();
}

int __wrap_cgroup_attach_task_pid(void *cg, pid_t pid) {
    check_expected_ptr(cg);
    check_expected(pid);
    return (int)mock();
}

int __wrap_cgroup_get_cgroup(void *cg) {
    (void)cg;
    return (int)mock();
}

int __wrap_cgroup_get_last_errno(void) { return (int)mock(); }

void __wrap_cgroup_free(void **cg) { (void)cg; }

int __wrap_close(int fd) {
    (void)fd;
    return 0;
}

int __wrap_bpf_object__open_skeleton(void *s, const void *opts) {
    (void)s;
    (void)opts;
    return (int)mock();
}

int __wrap_bpf_object__load_skeleton(void *s) {
    (void)s;
    return (int)mock();
}

void __wrap_bpf_object__destroy_skeleton(struct bpf_object_skeleton *s) {
    if (!s) {
        return;
    }
    free(s->maps);
    free(s->progs);
    free(s);
}

int __wrap_bpf_map__fd(const void *map) {
    (void)map;
    return (int)mock();
}

int __wrap_bpf_program__fd(const void *prog) {
    (void)prog;
    return (int)mock();
}

int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags) {
    (void)key;
    (void)value;
    (void)flags;
    check_expected(fd);
    return (int)mock();
}

int __wrap_bpf_prog_attach(int prog_fd, int target_fd, int type, unsigned int flags) {
    (void)flags;
    check_expected(prog_fd);
    check_expected(target_fd);
    check_expected(type);
    return (int)mock();
}

int __wrap_bpf_prog_detach(int target_fd, int type) {
    check_expected(target_fd);
    check_expected(type);
    return (int)mock();
}

int __wrap_open(const char *pathname, int flags, ...) {
    (void)flags;
    check_expected_ptr(pathname);
    return (int)mock();
}

static int mock_path_index = 0;
static char *mock_paths_next[] = {"1234", "5678", ""};

int __wrap_cgroup_walk_tree_begin(
    const char *controller,
    const char *base_path,
    int depth,
    void **handle,
    struct cgroup_file_info *info,
    int *base_level
) {
    (void)controller;
    (void)base_path;
    (void)depth;
    (void)handle;
    (void)base_level;
    mock_path_index = 0;
    if (info) {
        static char path_buffer[128];
        memset(info, 0, sizeof(*info));
        info->type = mock_type(enum cgroup_file_type);
        strcpy(path_buffer, "");
        info->path = path_buffer;
    }
    return (int)mock();
}

int __wrap_cgroup_walk_tree_next(
    int depth, void **handle, struct cgroup_file_info *info, int base_level
) {
    (void)depth;
    (void)handle;
    (void)base_level;
    if (info) {
        static char path_buffer[128];
        memset(info, 0, sizeof(*info));
        info->type = mock_type(enum cgroup_file_type);
        if (mock_path_index < 3) {
            strcpy(path_buffer, mock_paths_next[mock_path_index++]);
        } else {
            strcpy(path_buffer, "");
        }
        info->path = path_buffer;
    }
    return (int)mock();
}

int __wrap_cgroup_walk_tree_end(void **handle) {
    (void)handle;
    return (int)mock();
}

int __wrap_cgroup_get_subsys_mount_point(const char *controller, char *path) {
    (void)controller;
    (void)path;
    return (int)mock();
}

static void test_ratelimit_init_success(void **state) {
    (void)state;

    ratelimit_code result = ratelimit_init();

    assert_int_equal(result, RATELIMIT_OK);
}

static void test_limit_process_bandwidth(void **state) {
    (void)state;

    pid_t test_pid = 1234;
    rate_limit_config config = {.upload_kbps = 1000, .download_kbps = 2000};

    expect_string(__wrap_cgroup_new_cgroup, name, "strait");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x1000);
    will_return(__wrap_cgroup_create_cgroup, 0);

    expect_string(__wrap_cgroup_new_cgroup, name, "strait/1234");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x2000);
    will_return(__wrap_cgroup_create_cgroup, 0);

    expect_value(__wrap_cgroup_attach_task_pid, cg, (void *)0x2000);
    expect_value(__wrap_cgroup_attach_task_pid, pid, 1234);
    will_return(__wrap_cgroup_attach_task_pid, 0);

    will_return(__wrap_bpf_object__open_skeleton, 0);
    will_return(__wrap_bpf_object__load_skeleton, 0);
    will_return(__wrap_bpf_map__fd, 100);
    expect_value(__wrap_bpf_map_update_elem, fd, 100);
    will_return(__wrap_bpf_map_update_elem, 0);
    expect_value(__wrap_bpf_map_update_elem, fd, 100);
    will_return(__wrap_bpf_map_update_elem, 0);
    will_return(__wrap_bpf_program__fd, 101);
    expect_value(__wrap_bpf_prog_attach, prog_fd, 101);
    expect_value(__wrap_bpf_prog_attach, target_fd, 20);
    expect_value(__wrap_bpf_prog_attach, type, BPF_CGROUP_INET_EGRESS);
    will_return(__wrap_bpf_prog_attach, 0);
    will_return(__wrap_bpf_program__fd, 102);
    expect_value(__wrap_bpf_prog_attach, prog_fd, 102);
    expect_value(__wrap_bpf_prog_attach, target_fd, 20);
    expect_value(__wrap_bpf_prog_attach, type, BPF_CGROUP_INET_INGRESS);
    will_return(__wrap_bpf_prog_attach, 0);

    expect_string(__wrap_open, pathname, "/sys/fs/cgroup/strait/1234");
    will_return(__wrap_open, 20);

    ratelimit_code result = limit_process_bandwidth(test_pid, config);

    assert_int_equal(result, RATELIMIT_OK);
}

static void test_close_rate_limiter_handle_valid(void **state) {
    (void)state;

    rate_limiter *handle = malloc(256);
    assert_non_null(handle);

    memset(handle, 0, 256);

    close_rate_limiter_handle(handle);
}

static void test_unregister_rate_limiter_by_pid_success(void **state) {
    (void)state;

    pid_t test_pid = 5678;

    expect_string(__wrap_cgroup_new_cgroup, name, "strait/5678");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x3000);
    will_return(__wrap_cgroup_get_cgroup, 0);

    expect_string(__wrap_open, pathname, "/sys/fs/cgroup/strait/5678");
    will_return(__wrap_open, 30);

    expect_value(__wrap_bpf_prog_detach, target_fd, 30);
    expect_value(__wrap_bpf_prog_detach, type, BPF_CGROUP_INET_EGRESS);
    will_return(__wrap_bpf_prog_detach, 0);
    expect_value(__wrap_bpf_prog_detach, target_fd, 30);
    expect_value(__wrap_bpf_prog_detach, type, BPF_CGROUP_INET_INGRESS);
    will_return(__wrap_bpf_prog_detach, 0);

    will_return(__wrap_cgroup_delete_cgroup, 0);

    ratelimit_code result = unregister_rate_limiter_by_pid(test_pid);

    assert_int_equal(result, RATELIMIT_OK);
}

static void test_ratelimit_code_string(void **state) {
    (void)state;

    assert_string_equal(ratelimit_code_string(RATELIMIT_OK), "Success");
    assert_string_equal(ratelimit_code_string(RATELIMIT_INVALID_PID), "Invalid PID");
    assert_string_equal(ratelimit_code_string(RATELIMIT_BPF_OPEN), "Failed to open BPF object");
}

static void test_ratelimit_cleanup_all_no_parent(void **state) {
    (void)state;

    expect_string(__wrap_cgroup_new_cgroup, name, "strait");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x1000);
    will_return(__wrap_cgroup_get_cgroup, ECGOTHER);

    ratelimit_code result = ratelimit_cleanup_all();

    assert_int_equal(result, RATELIMIT_CLEANUP);
}

static void test_ratelimit_cleanup_all_success(void **state) {
    (void)state;

    expect_string(__wrap_cgroup_new_cgroup, name, "strait");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x1000);
    will_return(__wrap_cgroup_get_cgroup, 0);

    will_return(__wrap_cgroup_walk_tree_begin, CGROUP_FILE_TYPE_DIR);
    will_return(__wrap_cgroup_walk_tree_begin, 0);

    will_return(__wrap_cgroup_walk_tree_next, CGROUP_FILE_TYPE_DIR);
    will_return(__wrap_cgroup_walk_tree_next, 0);

    expect_string(__wrap_cgroup_new_cgroup, name, "strait/1234");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x2000);
    will_return(__wrap_cgroup_get_cgroup, 0);
    expect_string(__wrap_open, pathname, "/sys/fs/cgroup/strait/1234");
    will_return(__wrap_open, 10);
    expect_value(__wrap_bpf_prog_detach, target_fd, 10);
    expect_value(__wrap_bpf_prog_detach, type, BPF_CGROUP_INET_EGRESS);
    will_return(__wrap_bpf_prog_detach, 0);
    expect_value(__wrap_bpf_prog_detach, target_fd, 10);
    expect_value(__wrap_bpf_prog_detach, type, BPF_CGROUP_INET_INGRESS);
    will_return(__wrap_bpf_prog_detach, 0);
    will_return(__wrap_cgroup_delete_cgroup, 0);

    will_return(__wrap_cgroup_walk_tree_next, CGROUP_FILE_TYPE_DIR);
    will_return(__wrap_cgroup_walk_tree_next, 0);

    expect_string(__wrap_cgroup_new_cgroup, name, "strait/5678");
    will_return(__wrap_cgroup_new_cgroup, (void *)0x3000);
    will_return(__wrap_cgroup_get_cgroup, 0);
    expect_string(__wrap_open, pathname, "/sys/fs/cgroup/strait/5678");
    will_return(__wrap_open, 20);
    expect_value(__wrap_bpf_prog_detach, target_fd, 20);
    expect_value(__wrap_bpf_prog_detach, type, BPF_CGROUP_INET_EGRESS);
    will_return(__wrap_bpf_prog_detach, 0);
    expect_value(__wrap_bpf_prog_detach, target_fd, 20);
    expect_value(__wrap_bpf_prog_detach, type, BPF_CGROUP_INET_INGRESS);
    will_return(__wrap_bpf_prog_detach, 0);
    will_return(__wrap_cgroup_delete_cgroup, 0);

    will_return(__wrap_cgroup_walk_tree_next, CGROUP_FILE_TYPE_DIR);
    will_return(__wrap_cgroup_walk_tree_next, ECGEOF);

    will_return(__wrap_cgroup_walk_tree_end, 0);
    will_return(__wrap_cgroup_delete_cgroup, 0);

    ratelimit_code result = ratelimit_cleanup_all();

    assert_int_equal(result, RATELIMIT_OK);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ratelimit_init_success),
        cmocka_unit_test(test_limit_process_bandwidth),
        cmocka_unit_test(test_close_rate_limiter_handle_valid),
        cmocka_unit_test(test_unregister_rate_limiter_by_pid_success),
        cmocka_unit_test(test_ratelimit_code_string),
        cmocka_unit_test(test_ratelimit_cleanup_all_no_parent),
        cmocka_unit_test(test_ratelimit_cleanup_all_success),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
