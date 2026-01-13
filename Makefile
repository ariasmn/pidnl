CC = clang
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address

LIBSRC = lib/src
CLI_OBJ = cli/main.o
CLI_BIN = cli/strait
BPF_SRC = lib/src/ratelimit.bpf.c
BPF_OBJ = $(LIBSRC)/ratelimit.bpf.o
BPF_SKEL = $(LIBSRC)/ratelimit_bpf.skel.h

all: check-asan $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)

check-asan:
	@echo "int main(void){return 0;}" | $(CC) -fsanitize=address -x c - -o /dev/null 2>/dev/null || \
		(echo "Error: libasan not found" && exit 1)

$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BPF_OBJ): $(BPF_SRC)
	$(CC) -O2 -target bpf -g -c $< -o $@

$(CLI_BIN): $(LIBSRC)/discovery.o $(LIBSRC)/ratelimit.o $(CLI_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -L/usr/lib64 -lnl-3 -lnl-route-3 -lbpf -lelf -lz

$(LIBSRC)/%.o: $(LIBSRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

cli/%.o: cli/%.c
	$(CC) $(CFLAGS) -I$(LIBSRC) -c $< -o $@

TEST_SRC = tests/test_discovery.c
TEST_BIN = tests/test_discovery
TEST_OBJ = tests/discovery_test.o
TEST_CFLAGS = -Wall -Wextra -Werror -g -fPIE -I$(LIBSRC)

TEST_RATELIMIT_SRC = tests/test_ratelimit.c
TEST_RATELIMIT_BIN = tests/test_ratelimit
TEST_RATELIMIT_OBJ = tests/ratelimit_test.o

test: $(BPF_SKEL)
	@set -e; \
	mkdir -p tests; \
	cleanup() { rm -f $(TEST_BIN) $(TEST_OBJ) $(TEST_RATELIMIT_BIN) $(TEST_RATELIMIT_OBJ); }; \
	trap cleanup EXIT; \
	$(CC) $(TEST_CFLAGS) -I. -c $(LIBSRC)/discovery.c -o $(TEST_OBJ); \
	$(CC) $(TEST_CFLAGS) -I$(LIBSRC) -I. -c $(LIBSRC)/ratelimit.c -o $(TEST_RATELIMIT_OBJ); \
	$(CC) $(TEST_CFLAGS) -I. $(TEST_SRC) $(TEST_OBJ) -o $(TEST_BIN) \
		-Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=close -Wl,--wrap=sendmsg \
		-Wl,--wrap=recvmsg -Wl,--wrap=opendir -Wl,--wrap=readdir -Wl,--wrap=closedir \
		-Wl,--wrap=readlink -Wl,--wrap=fopen -Wl,--wrap=fgets -Wl,--wrap=fclose \
		-lcmocka -pie; \
	$(CC) $(TEST_CFLAGS) -I$(LIBSRC) -I. $(TEST_RATELIMIT_SRC) $(TEST_RATELIMIT_OBJ) -o $(TEST_RATELIMIT_BIN) \
		-Wl,--wrap=stat -Wl,--wrap=mkdir -Wl,--wrap=open -Wl,--wrap=close -Wl,--wrap=write \
		-Wl,--wrap=fdopendir -Wl,--wrap=readdir -Wl,--wrap=closedir -Wl,--wrap=rmdir \
		-Wl,--wrap=bpf_object__open_skeleton -Wl,--wrap=bpf_object__load_skeleton \
		-Wl,--wrap=bpf_object__destroy_skeleton \
		-Wl,--wrap=bpf_map__fd -Wl,--wrap=bpf_program__fd -Wl,--wrap=bpf_map_update_elem \
		-Wl,--wrap=bpf_prog_attach -Wl,--wrap=bpf_prog_detach -Wl,--wrap=unlinkat \
		-lcmocka -lbpf -pie; \
	./tests/test_discovery; \
	./tests/test_ratelimit

clean:
	rm -f $(LIBSRC)/*.o cli/*.o $(CLI_BIN) $(BPF_OBJ) $(BPF_SKEL) $(TEST_OBJ) $(TEST_BIN) $(TEST_RATELIMIT_OBJ) $(TEST_RATELIMIT_BIN)

.PHONY: all clean check-asan test
