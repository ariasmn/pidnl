#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/discovery.h"

static void test_discovery_code_string_valid_codes(void **state) {
    (void)state;
    assert_string_not_equal(
        discovery_code_string(DISCOVERY_OK), "Unknown error"
    );
    assert_string_not_equal(
        discovery_code_string(DISCOVERY_ALLOC), "Unknown error"
    );
    assert_string_not_equal(
        discovery_code_string(DISCOVERY_SOCKET), "Unknown error"
    );
    assert_string_not_equal(
        discovery_code_string(DISCOVERY_BIND), "Unknown error"
    );
    assert_string_not_equal(
        discovery_code_string(DISCOVERY_RECVMSG), "Unknown error"
    );
    assert_string_not_equal(
        discovery_code_string(DISCOVERY_NETLINK_MSG), "Unknown error"
    );
}

static void test_discovery_code_string_invalid_codes(void **state) {
    (void)state;
    assert_string_equal(discovery_code_string(999), "Unknown error");
    assert_string_equal(discovery_code_string(-1), "Unknown error");
}

static void test_destroy_process_list_null(void **state) {
    (void)state;
    destroy_process_list(NULL);
}

static void test_get_network_processes_returns_ok(void **state) {
    (void)state;
    process_list *list = NULL;
    discovery_code code = get_network_processes(&list);
    assert_int_equal(code, DISCOVERY_OK);
    assert_non_null(list);
    assert_non_null(list->processes);
    destroy_process_list(list);
}

static void test_get_network_processes_finds_tcp(void **state) {
    (void)state;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    assert_int_not_equal(sock, -1);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    assert_int_equal(bind(sock, (struct sockaddr *)&addr, sizeof(addr)), 0);
    listen(sock, 1);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    pid_t my_pid = getpid();
    int found = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == my_pid) {
            found = 1;
            assert_int_equal(list->processes[i].has_tcp, 1);
            break;
        }
    }
    assert_int_equal(found, 1);

    close(sock);
    destroy_process_list(list);
}

static void test_get_network_processes_finds_udp(void **state) {
    (void)state;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert_int_not_equal(sock, -1);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    assert_int_equal(bind(sock, (struct sockaddr *)&addr, sizeof(addr)), 0);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    pid_t my_pid = getpid();
    int found = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == my_pid) {
            found = 1;
            assert_int_equal(list->processes[i].has_udp, 1);
            break;
        }
    }
    assert_int_equal(found, 1);

    close(sock);
    destroy_process_list(list);
}

static void test_get_network_processes_finds_tcp_and_udp(void **state) {
    (void)state;
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert_int_not_equal(tcp_sock, -1);
    assert_int_not_equal(udp_sock, -1);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    assert_int_equal(bind(tcp_sock, (struct sockaddr *)&addr, sizeof(addr)), 0);
    listen(tcp_sock, 1);
    assert_int_equal(bind(udp_sock, (struct sockaddr *)&addr, sizeof(addr)), 0);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    pid_t my_pid = getpid();
    int found = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == my_pid) {
            found = 1;
            assert_int_equal(list->processes[i].has_tcp, 1);
            assert_int_equal(list->processes[i].has_udp, 1);
            assert_true(list->processes[i].num_connections >= 2);
            break;
        }
    }
    assert_int_equal(found, 1);

    close(tcp_sock);
    close(udp_sock);
    destroy_process_list(list);
}

static void test_get_network_processes_valid_pids(void **state) {
    (void)state;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(sock, 1);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    for (size_t i = 0; i < list->count; i++) {
        assert_true(list->processes[i].pid > 0);
    }

    close(sock);
    destroy_process_list(list);
}

static void test_get_network_processes_has_name(void **state) {
    (void)state;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(sock, 1);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    pid_t my_pid = getpid();
    int found = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == my_pid) {
            found = 1;
            assert_true(strlen(list->processes[i].process_name) > 0);
            break;
        }
    }
    assert_int_equal(found, 1);

    close(sock);
    destroy_process_list(list);
}

static void test_get_network_processes_has_exe_path(void **state) {
    (void)state;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(sock, 1);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    pid_t my_pid = getpid();
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == my_pid) {
            assert_true(strlen(list->processes[i].exe_path) > 0);
            break;
        }
    }

    close(sock);
    destroy_process_list(list);
}

static void test_get_network_processes_counts_connections(void **state) {
    (void)state;
    int sock1 = socket(AF_INET, SOCK_STREAM, 0);
    int sock2 = socket(AF_INET, SOCK_STREAM, 0);
    assert_int_not_equal(sock1, -1);
    assert_int_not_equal(sock2, -1);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    assert_int_equal(bind(sock1, (struct sockaddr *)&addr, sizeof(addr)), 0);
    assert_int_equal(bind(sock2, (struct sockaddr *)&addr, sizeof(addr)), 0);
    listen(sock1, 1);
    listen(sock2, 1);

    process_list *list = NULL;
    assert_int_equal(get_network_processes(&list), DISCOVERY_OK);

    pid_t my_pid = getpid();
    for (size_t i = 0; i < list->count; i++) {
        if (list->processes[i].pid == my_pid) {
            assert_true(list->processes[i].num_connections >= 2);
            break;
        }
    }

    close(sock1);
    close(sock2);
    destroy_process_list(list);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_discovery_code_string_valid_codes),
        cmocka_unit_test(test_discovery_code_string_invalid_codes),
        cmocka_unit_test(test_destroy_process_list_null),
        cmocka_unit_test(test_get_network_processes_returns_ok),
        cmocka_unit_test(test_get_network_processes_finds_tcp),
        cmocka_unit_test(test_get_network_processes_finds_udp),
        cmocka_unit_test(test_get_network_processes_finds_tcp_and_udp),
        cmocka_unit_test(test_get_network_processes_valid_pids),
        cmocka_unit_test(test_get_network_processes_has_name),
        cmocka_unit_test(test_get_network_processes_has_exe_path),
        cmocka_unit_test(test_get_network_processes_counts_connections),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
