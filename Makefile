CC = clang
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address

LIBSRC = lib/src
CLI_OBJ = cli/main.o
CLI_BIN = cli/strait
BPF_SRC = lib/src/ratelimit.bpf.c
BPF_OBJ = $(LIBSRC)/ratelimit.bpf.o
BPF_SKEL = $(LIBSRC)/ratelimit_bpf.skel.h

check-deps:
	@which clang >/dev/null 2>&1 || (echo "clang: MISSING" && exit 1)
	@which bpftool >/dev/null 2>&1 || (echo "bpftool: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libasan.so || (echo "libasan: MISSING" && exit 1)
	@pkg-config --exists cmocka 2>/dev/null || (echo "libcmocka: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libnl-3.so || (echo "libnl-3: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libnl-route-3.so || (echo "libnl-route-3: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libbpf.so || (echo "libbpf: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libelf.so || (echo "libelf: MISSING" && exit 1)
	@which valgrind >/dev/null 2>&1 || (echo "valgrind: MISSING" && exit 1)

dev: clean check-deps $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)
$(BPF_SKEL): $(BPF_OBJ)
	@bpftool gen skeleton $< > $@

$(BPF_OBJ): $(BPF_SRC)
	@$(CC) -O2 -target bpf -g -c $< -o $@

$(CLI_BIN): $(LIBSRC)/discovery.o $(LIBSRC)/ratelimit.o $(CLI_OBJ)
	@$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -L/usr/lib64 -lnl-3 -lnl-route-3 -lbpf -lelf -lcgroup

$(LIBSRC)/%.o: $(LIBSRC)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

cli/%.o: cli/%.c
	@$(CC) $(CFLAGS) -I$(LIBSRC) -c $< -o $@

TEST_SRC = tests/test_discovery.c
TEST_BIN = tests/test_discovery
TEST_OBJ = tests/discovery_test.o
TEST_CFLAGS = -Wall -Wextra -Werror -g -fPIE -I$(LIBSRC)

TEST_RATELIMIT_SRC = tests/test_ratelimit.c
TEST_RATELIMIT_BIN = tests/test_ratelimit
TEST_RATELIMIT_OBJ = tests/ratelimit_test.o

test: clean $(BPF_SKEL)
	@set -e; \
	mkdir -p tests 2>/dev/null; \
	cleanup() { rm -f $(TEST_BIN) $(TEST_OBJ) $(TEST_RATELIMIT_BIN) $(TEST_RATELIMIT_OBJ) 2>/dev/null; }; \
	trap cleanup EXIT; \
	$(CC) $(TEST_CFLAGS) -I. -c $(LIBSRC)/discovery.c -o $(TEST_OBJ); \
	$(CC) $(TEST_CFLAGS) -I$(LIBSRC) -I. -c $(LIBSRC)/ratelimit.c -o $(TEST_RATELIMIT_OBJ); \
	$(CC) $(TEST_CFLAGS) -I. $(TEST_SRC) $(TEST_OBJ) -o $(TEST_BIN) \
		-Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=close -Wl,--wrap=sendmsg \
		-Wl,--wrap=recvmsg -Wl,--wrap=opendir -Wl,--wrap=readdir -Wl,--wrap=closedir \
		-Wl,--wrap=readlink -Wl,--wrap=fopen -Wl,--wrap=fgets -Wl,--wrap=fclose \
		-lcmocka -pie; \
	$(CC) $(TEST_CFLAGS) -I$(LIBSRC) -I. $(TEST_RATELIMIT_SRC) $(TEST_RATELIMIT_OBJ) -o $(TEST_RATELIMIT_BIN) \
		-Wl,--wrap=cgroup_init -Wl,--wrap=cgroup_new_cgroup -Wl,--wrap=cgroup_create_cgroup \
		-Wl,--wrap=cgroup_delete_cgroup -Wl,--wrap=cgroup_attach_task_pid -Wl,--wrap=cgroup_get_cgroup \
		-Wl,--wrap=cgroup_get_last_errno -Wl,--wrap=cgroup_free \
		-Wl,--wrap=open -Wl,--wrap=close \
		-Wl,--wrap=cgroup_walk_tree_begin -Wl,--wrap=cgroup_walk_tree_next -Wl,--wrap=cgroup_walk_tree_end \
		-Wl,--wrap=cgroup_get_subsys_mount_point \
		-Wl,--wrap=bpf_object__open_skeleton -Wl,--wrap=bpf_object__load_skeleton \
		-Wl,--wrap=bpf_object__destroy_skeleton \
		-Wl,--wrap=bpf_map__fd -Wl,--wrap=bpf_program__fd -Wl,--wrap=bpf_map_update_elem \
		-Wl,--wrap=bpf_prog_attach -Wl,--wrap=bpf_prog_detach \
		-Wl,--wrap=ratelimit_bpf__destroy \
		-lcmocka -lbpf -lcgroup -pie; \
	./tests/test_discovery; \
	./tests/test_ratelimit

valgrind: clean $(BPF_SKEL)
	@mkdir -p tests 2>/dev/null; \
	cleanup() { rm -f $(TEST_BIN) $(TEST_OBJ) $(TEST_RATELIMIT_BIN) $(TEST_RATELIMIT_OBJ) 2>/dev/null; }; \
	trap cleanup EXIT; \
	$(CC) $(TEST_CFLAGS) -I. -c $(LIBSRC)/discovery.c -o $(TEST_OBJ) 2>/dev/null; \
	$(CC) $(TEST_CFLAGS) -I$(LIBSRC) -I. -c $(LIBSRC)/ratelimit.c -o $(TEST_RATELIMIT_OBJ) 2>/dev/null; \
	$(CC) $(TEST_CFLAGS) -I. $(TEST_SRC) $(TEST_OBJ) -o $(TEST_BIN) \
	        -Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=close -Wl,--wrap=sendmsg \
	        -Wl,--wrap=recvmsg -Wl,--wrap=opendir -Wl,--wrap=readdir -Wl,--wrap=closedir \
	        -Wl,--wrap=readlink -Wl,--wrap=fopen -Wl,--wrap=fgets -Wl,--wrap=fclose \
	        -lcmocka -pie 2>/dev/null; \
	$(CC) $(TEST_CFLAGS) -I$(LIBSRC) -I. $(TEST_RATELIMIT_SRC) $(TEST_RATELIMIT_OBJ) -o $(TEST_RATELIMIT_BIN) \
	        -Wl,--wrap=cgroup_init -Wl,--wrap=cgroup_new_cgroup -Wl,--wrap=cgroup_create_cgroup \
	        -Wl,--wrap=cgroup_delete_cgroup -Wl,--wrap=cgroup_attach_task_pid -Wl,--wrap=cgroup_get_cgroup \
	        -Wl,--wrap=cgroup_get_last_errno -Wl,--wrap=cgroup_free \
	        -Wl,--wrap=open -Wl,--wrap=close \
	        -Wl,--wrap=cgroup_walk_tree_begin -Wl,--wrap=cgroup_walk_tree_next -Wl,--wrap=cgroup_walk_tree_end \
	        -Wl,--wrap=cgroup_get_subsys_mount_point \
	        -Wl,--wrap=bpf_object__open_skeleton -Wl,--wrap=bpf_object__load_skeleton \
	        -Wl,--wrap=bpf_object__destroy_skeleton \
	        -Wl,--wrap=bpf_map__fd -Wl,--wrap=bpf_program__fd -Wl,--wrap=bpf_map_update_elem \
	        -Wl,--wrap=bpf_prog_attach -Wl,--wrap=bpf_prog_detach \
	        -Wl,--wrap=ratelimit_bpf__destroy \
	        -lcmocka -lbpf -lcgroup -pie 2>/dev/null; \
	valgrind --log-fd=3 --leak-check=full --show-leak-kinds=all \
	        --errors-for-leak-kinds=definite,indirect --error-exitcode=1 ./tests/test_discovery 3>/dev/null >/dev/null 2>&1; \
	valgrind --log-fd=3 --leak-check=full --show-leak-kinds=all \
	        --errors-for-leak-kinds=definite,indirect --error-exitcode=1 ./tests/test_ratelimit 3>/dev/null >/dev/null 2>&1

clean:
	@rm -f $(LIBSRC)/*.o cli/*.o $(CLI_BIN) $(BPF_OBJ) $(BPF_SKEL) $(TEST_OBJ) $(TEST_BIN) $(TEST_RATELIMIT_OBJ) $(TEST_RATELIMIT_BIN) 2>/dev/null

lint:
	@clang-format --dry-run --Werror cli/*.c lib/src/*.c tests/*.c

.PHONY: dev clean check-deps test valgrind lint
