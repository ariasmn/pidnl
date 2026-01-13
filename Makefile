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

clean:
	rm -f $(LIBSRC)/*.o cli/*.o $(CLI_BIN) $(BPF_OBJ) $(BPF_SKEL)

# Test configuration
TEST_SRC = tests/test_discovery.c
TEST_BIN = tests/test_discovery
TEST_OBJ = tests/discovery_test.o
TEST_CFLAGS = -Wall -Wextra -Werror -g -fPIE

$(TEST_OBJ): $(LIBSRC)/discovery.c
	@mkdir -p tests
	$(CC) $(TEST_CFLAGS) -I. -c $< -o $@

test-build: $(TEST_OBJ)
	$(CC) $(TEST_CFLAGS) -I. $(TEST_SRC) $(TEST_OBJ) -o $(TEST_BIN) -pie

CONTAINER_ENGINE ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)

test:
	@$(CONTAINER_ENGINE) build --quiet -f tests/Dockerfile -t strait-test . >/dev/null 2>&1
	@$(CONTAINER_ENGINE) run --rm --cap-add=NET_ADMIN strait-test

.PHONY: all clean check-asan test test-build
