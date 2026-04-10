CC = clang
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address
ARCH_INCLUDE = /usr/include/$(shell $(CC) -print-multiarch 2>/dev/null || echo "$(shell uname -m)-linux-gnu")

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
	@ldconfig -p 2>/dev/null | grep -q libnl-3.so || (echo "libnl-3: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libnl-route-3.so || (echo "libnl-route-3: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libbpf.so || (echo "libbpf: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libelf.so || (echo "libelf: MISSING" && exit 1)

dev: clean check-deps $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)
$(BPF_SKEL): $(BPF_OBJ)
	@bpftool gen skeleton $< > $@

$(BPF_OBJ): $(BPF_SRC)
	@$(CC) -O2 -target bpf -g -I$(ARCH_INCLUDE) -c $< -o $@

$(CLI_BIN): $(LIBSRC)/discovery.o $(LIBSRC)/ratelimit.o $(LIBSRC)/monitor.o $(CLI_OBJ)
	@$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -L/usr/lib64 -lnl-3 -lnl-route-3 -lbpf -lelf -lcgroup

$(LIBSRC)/%.o: $(LIBSRC)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

cli/%.o: cli/%.c
	@$(CC) $(CFLAGS) -I$(LIBSRC) -c $< -o $@

clean:
	@rm -f $(LIBSRC)/*.o cli/*.o $(CLI_BIN) $(BPF_OBJ) $(BPF_SKEL) 2>/dev/null

lint:
	@clang-format --dry-run --Werror cli/*.c lib/src/*.c

test:
	@if [ "$$(id -u)" -ne 0 ]; then echo "error: tests require root (run with sudo)" && exit 1; fi
	@bash tests/run.sh

.PHONY: dev clean check-deps lint test
