#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lib/src/discovery.h"
#include "test.h"

int main(void) {
    RUN_TESTS(
        TEST("test_discovery_code_string"); {
            ASSERT_STRING_NOT_EQUAL(
                discovery_code_string(DISCOVERY_OK), "Unknown error"
            );
            ASSERT_STRING_NOT_EQUAL(
                discovery_code_string(DISCOVERY_ALLOC), "Unknown error"
            );
            ASSERT_STRING_NOT_EQUAL(
                discovery_code_string(DISCOVERY_SOCKET), "Unknown error"
            );
            ASSERT_STRING_NOT_EQUAL(
                discovery_code_string(DISCOVERY_BIND), "Unknown error"
            );
            ASSERT_STRING_NOT_EQUAL(
                discovery_code_string(DISCOVERY_RECVMSG), "Unknown error"
            );
            ASSERT_STRING_NOT_EQUAL(
                discovery_code_string(DISCOVERY_NETLINK_MSG), "Unknown error"
            );
            ASSERT_STRING_EQUAL(discovery_code_string(999), "Unknown error");
            ASSERT_STRING_EQUAL(discovery_code_string(-1), "Unknown error");
        } END_TEST;

        TEST("test_destroy_process_list");
        { destroy_process_list(NULL); } END_TEST;

        TEST("test_get_network_processes"); {
            int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
            int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            ASSERT_INT_NOT_EQUAL(tcp_sock, -1);
            ASSERT_INT_NOT_EQUAL(udp_sock, -1);

            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            ASSERT_INT_EQUAL(
                bind(tcp_sock, (struct sockaddr *)&addr, sizeof(addr)), 0
            );
            ASSERT_INT_EQUAL(
                bind(udp_sock, (struct sockaddr *)&addr, sizeof(addr)), 0
            );
            listen(tcp_sock, 1);

            process_list *list = NULL;
            ASSERT_INT_EQUAL(get_network_processes(&list), DISCOVERY_OK);
            ASSERT_NON_NULL(list);
            ASSERT_NON_NULL(list->processes);

            pid_t my_pid = getpid();
            int found = 0;
            for (size_t i = 0; i < list->count; i++) {
                if (list->processes[i].pid == my_pid) {
                    found = 1;
                    ASSERT_TRUE(list->processes[i].pid > 0);
                    ASSERT_TRUE(strlen(list->processes[i].process_name) > 0);
                    ASSERT_TRUE(strlen(list->processes[i].exe_path) > 0);
                    ASSERT_INT_EQUAL(list->processes[i].has_tcp, 1);
                    ASSERT_INT_EQUAL(list->processes[i].has_udp, 1);
                    ASSERT_TRUE(list->processes[i].num_connections >= 2);
                    break;
                }
            }
            ASSERT_INT_EQUAL(found, 1);

            close(tcp_sock);
            close(udp_sock);
            destroy_process_list(list);
        } END_TEST;
    );
}
