#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <dirent.h>
#include <errno.h>

#include "discovery.h"

/* Mock wrappers */

int __wrap_socket(int domain, int type, int protocol) {
    check_expected(domain);
    check_expected(type);
    check_expected(protocol);
    return (int)mock();
}

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addr;
    (void)addrlen;
    check_expected(sockfd);
    return (int)mock();
}

int __wrap_close(int fd) {
    check_expected(fd);
    return (int)mock();
}

ssize_t __wrap_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    (void)msg;
    (void)flags;
    check_expected(sockfd);
    return (ssize_t)mock();
}

/* Global to control recvmsg behavior */
static int recvmsg_call_count = 0;

ssize_t __wrap_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    (void)flags;
    check_expected(sockfd);

    recvmsg_call_count++;

    int behavior = (int)mock();

    if (behavior == -1) {
        errno = EINVAL;
        return -1;
    }

    if (behavior == 0) {
        return 0;
    }

    char *buf = (char *)msg->msg_iov->iov_base;

    /* First call: return actual diagnostic message */
    if (recvmsg_call_count == 1) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        struct inet_diag_msg *diag = (struct inet_diag_msg *)NLMSG_DATA(nlh);

        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_msg));
        nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
        nlh->nlmsg_flags = NLM_F_MULTI;
        nlh->nlmsg_seq = 0;
        nlh->nlmsg_pid = 0;

        memset(diag, 0, sizeof(struct inet_diag_msg));
        diag->idiag_family = AF_INET;
        diag->idiag_state = 0x01;  /* TCP_ESTABLISHED */
        diag->idiag_uid = 1000;    /* Non-root user */
        diag->idiag_inode = 12345; /* Test inode */

        return nlh->nlmsg_len;
    }

    /* Second call: return DONE */
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(0);
    nlh->nlmsg_type = NLMSG_DONE;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = 0;

    return sizeof(struct nlmsghdr);
}

/* Mock dirent structures */
static struct dirent proc_entry_1234 = {.d_name = "1234"};
static struct dirent fd_entry_3 = {.d_name = "3"};

static int opendir_call_count = 0;

DIR *__wrap_opendir(const char *name) {
    check_expected(name);
    opendir_call_count++;
    return (DIR *)mock();
}

static int readdir_call_count = 0;

struct dirent *__wrap_readdir(DIR *dirp) {
    check_expected(dirp);
    readdir_call_count++;
    return (struct dirent *)mock();
}

int __wrap_closedir(DIR *dirp) {
    check_expected(dirp);
    return (int)mock();
}

static int readlink_call_count = 0;

ssize_t __wrap_readlink(const char *pathname, char *buf, size_t bufsiz) {
    check_expected(pathname);
    readlink_call_count++;

    ssize_t ret = (ssize_t)mock();
    if (ret > 0) {
        const char *link_target = (const char *)mock();
        if (link_target) {
            size_t len = strlen(link_target);
            if (len > bufsiz - 1)
                len = bufsiz - 1;
            memcpy(buf, link_target, len);
            return len;
        }
    }
    return ret;
}

FILE *__wrap_fopen(const char *pathname, const char *mode) {
    (void)mode;
    check_expected(pathname);
    return (FILE *)mock();
}

char *__wrap_fgets(char *s, int size, FILE *stream) {
    check_expected(stream);

    char *ret = (char *)mock();
    if (ret) {
        const char *content = (const char *)mock();
        strncpy(s, content, size - 1);
        s[size - 1] = '\0';
        return s;
    }
    return NULL;
}

int __wrap_fclose(FILE *stream) {
    check_expected(stream);
    return (int)mock();
}

/* Test: Find a process with matching inode */
static void test_get_network_processes_finds_process(void **state) {
    (void)state;

    /* Socket creation */
    expect_value(__wrap_socket, domain, AF_NETLINK);
    expect_value(__wrap_socket, type, SOCK_DGRAM);
    expect_value(__wrap_socket, protocol, NETLINK_SOCK_DIAG);
    will_return(__wrap_socket, 3);

    /* Bind */
    expect_value(__wrap_bind, sockfd, 3);
    will_return(__wrap_bind, 0);

    /* === Query TCP IPv4 === */
    expect_value(__wrap_sendmsg, sockfd, 3);
    will_return(__wrap_sendmsg, 32);

    /* First recvmsg returns diagnostic message with inode 12345 */
    expect_value(__wrap_recvmsg, sockfd, 3);
    will_return(__wrap_recvmsg, 1); /* Return diagnostic message */

    /* Now find_pid_by_inode is called - scan /proc */
    expect_string(__wrap_opendir, name, "/proc");
    will_return(__wrap_opendir, (DIR *)0x1000);

    /* readdir returns process 1234 */
    expect_value(__wrap_readdir, dirp, (DIR *)0x1000);
    will_return(__wrap_readdir, &proc_entry_1234);

    /* Open /proc/1234/fd */
    expect_string(__wrap_opendir, name, "/proc/1234/fd");
    will_return(__wrap_opendir, (DIR *)0x2000);

    /* readdir returns fd 3 */
    expect_value(__wrap_readdir, dirp, (DIR *)0x2000);
    will_return(__wrap_readdir, &fd_entry_3);

    /* readlink on /proc/1234/fd/3 returns socket:[12345] */
    expect_string(__wrap_readlink, pathname, "/proc/1234/fd/3");
    will_return(__wrap_readlink, 15);
    will_return(__wrap_readlink, "socket:[12345]");

    /* Found it! Close fd dir */
    expect_value(__wrap_closedir, dirp, (DIR *)0x2000);
    will_return(__wrap_closedir, 0);

    /* Close proc dir */
    expect_value(__wrap_closedir, dirp, (DIR *)0x1000);
    will_return(__wrap_closedir, 0);

    /* Now add_process_list reads /proc/1234/comm */
    expect_string(__wrap_fopen, pathname, "/proc/1234/comm");
    will_return(__wrap_fopen, (FILE *)0x3000);

    expect_value(__wrap_fgets, stream, (FILE *)0x3000);
    will_return(__wrap_fgets, (char *)1);
    will_return(__wrap_fgets, "testprocess\n");

    expect_value(__wrap_fclose, stream, (FILE *)0x3000);
    will_return(__wrap_fclose, 0);

    /* Read /proc/1234/exe */
    expect_string(__wrap_readlink, pathname, "/proc/1234/exe");
    will_return(__wrap_readlink, 9);
    will_return(__wrap_readlink, "/bin/test");

    /* Second recvmsg returns DONE */
    expect_value(__wrap_recvmsg, sockfd, 3);
    will_return(__wrap_recvmsg, 0); /* DONE */

    /* === Query TCP IPv6 === */
    expect_value(__wrap_sendmsg, sockfd, 3);
    will_return(__wrap_sendmsg, 32);
    expect_value(__wrap_recvmsg, sockfd, 3);
    will_return(__wrap_recvmsg, 0);

    /* === Query UDP IPv4 === */
    expect_value(__wrap_sendmsg, sockfd, 3);
    will_return(__wrap_sendmsg, 32);
    expect_value(__wrap_recvmsg, sockfd, 3);
    will_return(__wrap_recvmsg, 0);

    /* === Query UDP IPv6 === */
    expect_value(__wrap_sendmsg, sockfd, 3);
    will_return(__wrap_sendmsg, 32);
    expect_value(__wrap_recvmsg, sockfd, 3);
    will_return(__wrap_recvmsg, 0);

    /* Close socket */
    expect_value(__wrap_close, fd, 3);
    will_return(__wrap_close, 0);

    process_list *list = NULL;
    discovery_code result = get_network_processes(&list);

    assert_int_equal(result, DISCOVERY_OK);
    assert_int_equal(list->count, 1);
    assert_int_equal(list->processes[0].pid, 1234);
    assert_string_equal(list->processes[0].process_name, "testprocess");
    assert_string_equal(list->processes[0].exe_path, "/bin/test");
    assert_int_equal(list->processes[0].has_tcp, 1);
    assert_int_equal(list->processes[0].has_udp, 0);
    assert_int_equal(list->processes[0].num_connections, 1);

    destroy_process_list(list);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_network_processes_finds_process)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}