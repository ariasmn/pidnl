#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/limits.h>
#include <dirent.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

#include "ratelimit.h"

int __wrap_bpf_object__open_skeleton(
    struct bpf_object_skeleton *s, const struct bpf_object_open_opts *opts
) {
    (void)s;
    (void)opts;
    return (int)mock();
}

int __wrap_bpf_object__load_skeleton(struct bpf_object_skeleton *s) {
    (void)s;
    return (int)mock();
}

void __wrap_bpf_object__destroy_skeleton(struct bpf_object_skeleton *s) {
    (void)s;
}

int __wrap_bpf_map__fd(const struct bpf_map *map) {
    (void)map;
    return (int)mock();
}

int __wrap_bpf_program__fd(const struct bpf_program *prog) {
    (void)prog;
    return (int)mock();
}

int __wrap_bpf_map_update_elem(
    int fd, const void *key, const void *value, __u64 flags
) {
    (void)key;
    (void)value;
    (void)flags;
    check_expected(fd);
    return (int)mock();
}

int __wrap_bpf_prog_attach(
    int prog_fd, int target_fd, int type, unsigned int flags
) {
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

int __wrap_stat(const char *pathname, struct stat *statbuf) {
    (void)statbuf;
    check_expected_ptr(pathname);
    return (int)mock();
}

int __wrap_mkdir(const char *pathname, mode_t mode) {
    (void)mode;
    check_expected_ptr(pathname);
    return (int)mock();
}

int __wrap_open(const char *pathname, int flags, ...) {
    (void)flags;
    check_expected_ptr(pathname);
    return (int)mock();
}

int __wrap_close(int fd) {
    check_expected(fd);
    return (int)mock();
}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
    (void)count;
    check_expected(fd);
    check_expected_ptr(buf);
    return (ssize_t)mock();
}

int __wrap_rmdir(const char *pathname) {
    check_expected_ptr(pathname);
    return (int)mock();
}

DIR *__wrap_fdopendir(int fd) {
    check_expected(fd);
    return (DIR *)mock();
}

struct dirent *__wrap_readdir(DIR *dirp) {
    check_expected_ptr(dirp);
    return (struct dirent *)mock();
}

int __wrap_closedir(DIR *dirp) {
    check_expected_ptr(dirp);
    return (int)mock();
}

int __wrap_unlinkat(int dirfd, const char *pathname, int flags) {
    (void)flags;
    check_expected(dirfd);
    check_expected_ptr(pathname);
    return (int)mock();
}

static void test_limit_process_bandwidth(void **state) {
    (void)state;

    pid_t test_pid = 1234;
    rate_limit_config config = {.upload_kbps = 1000, .download_kbps = 2000};

    /* cleanup_orphaned_cgroup - stat returns -1 (no existing cgroup) */
    expect_string(__wrap_stat, pathname, "/sys/fs/cgroup/strait/1234");
    will_return(__wrap_stat, -1);

    /* ensure_parent_cgroup - check if parent exists */
    expect_string(__wrap_stat, pathname, "/sys/fs/cgroup/strait");
    will_return(__wrap_stat, 0); /* exists */

    /* setup_cgroup - create process cgroup */
    expect_string(__wrap_mkdir, pathname, "/sys/fs/cgroup/strait/1234");
    will_return(__wrap_mkdir, 0);

    /* open cgroup.procs */
    expect_string(
        __wrap_open, pathname, "/sys/fs/cgroup/strait/1234/cgroup.procs"
    );
    will_return(__wrap_open, 10);

    /* write PID */
    expect_value(__wrap_write, fd, 10);
    expect_string(__wrap_write, buf, "1234");
    will_return(__wrap_write, 4);

    expect_value(__wrap_close, fd, 10);
    will_return(__wrap_close, 0);

    /* attach_bpf_programs - open BPF skeleton */
    will_return(__wrap_bpf_object__open_skeleton, 0);

    /* load BPF */
    will_return(__wrap_bpf_object__load_skeleton, 0);

    /* Get map fd */
    will_return(__wrap_bpf_map__fd, 100);

    /* Update upload rate */
    expect_value(__wrap_bpf_map_update_elem, fd, 100);
    will_return(__wrap_bpf_map_update_elem, 0);

    /* Update download rate */
    expect_value(__wrap_bpf_map_update_elem, fd, 100);
    will_return(__wrap_bpf_map_update_elem, 0);

    /* Open cgroup for attaching */
    expect_string(__wrap_open, pathname, "/sys/fs/cgroup/strait/1234");
    will_return(__wrap_open, 20);

    /* bpf_program__fd for egress */
    will_return(__wrap_bpf_program__fd, 101);

    /* Attach egress program */
    expect_value(__wrap_bpf_prog_attach, prog_fd, 101);
    expect_value(__wrap_bpf_prog_attach, target_fd, 20);
    expect_value(__wrap_bpf_prog_attach, type, BPF_CGROUP_INET_EGRESS);
    will_return(__wrap_bpf_prog_attach, 0);

    /* bpf_program__fd for ingress */
    will_return(__wrap_bpf_program__fd, 102);

    /* Attach ingress program */
    expect_value(__wrap_bpf_prog_attach, prog_fd, 102);
    expect_value(__wrap_bpf_prog_attach, target_fd, 20);
    expect_value(__wrap_bpf_prog_attach, type, BPF_CGROUP_INET_INGRESS);
    will_return(__wrap_bpf_prog_attach, 0);

    ratelimit_code result = limit_process_bandwidth(test_pid, config);

    assert_int_equal(result, RATELIMIT_OK);
}

static void test_ratelimit_code_string(void **state) {
    (void)state;

    assert_string_equal(ratelimit_code_string(RATELIMIT_OK), "Success");
    assert_string_equal(
        ratelimit_code_string(RATELIMIT_INVALID_PID), "Invalid PID"
    );
    assert_string_equal(
        ratelimit_code_string(RATELIMIT_BPF_OPEN), "Failed to open BPF object"
    );
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_limit_process_bandwidth),
        cmocka_unit_test(test_ratelimit_code_string),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
