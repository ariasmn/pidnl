CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address

# Directories
LIBSRC = lib/src

# Include paths
INCLUDES = -I$(LIBSRC)

# Library link flags
LIBNL_LDFLAGS = $(shell pkg-config --libs libnl-3.0 libnl-route-3.0 2>/dev/null)
LIBBPF_LDFLAGS = -lbpf -lelf -lz

# Library
LIB_OBJ = $(LIBSRC)/strait.o

# CLI
CLI_OBJ = cli/main.o
CLI_BIN = cli/strait

# eBPF
BPF_SRC = lib/src/ratelimit.bpf.c
BPF_OBJ = $(LIBSRC)/ratelimit.bpf.o

.PHONY: all clean cli check-asan check-libbpf bpf

all: check-asan cli

check-asan:
	@echo "int main(void){return 0;}" | $(CC) -fsanitize=address -x c - -o /dev/null 2>/dev/null || \
		(echo "Error: libasan not found" && exit 1)

check-libbpf:
	@echo "int main(void){return 0;}" | $(CC) $(CFLAGS) -lbpf -x c - -o /dev/null 2>/dev/null || \
		(echo "Error: libbpf not found. Install with:" && \
		 echo "  Debian/Ubuntu: apt install libbpf-dev" && \
		 echo "  Fedora/RHEL: dnf install libbpf-devel" && \
		 echo "  Arch: pacman -S libbpf" && exit 1)

bpf: check-libbpf $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -target bpf -g -c $< -o $@

$(LIBSRC)/%.o: $(LIBSRC)/%.c $(LIBSRC)/%.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

cli/%.o: cli/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

cli: $(CLI_BIN)

$(CLI_BIN): $(LIB_OBJ) $(CLI_OBJ)
	$(CC) $(LDFLAGS) $(LIB_OBJ) $(CLI_OBJ) -o $@ $(LIBNL_LDFLAGS) $(LIBBPF_LDFLAGS)

clean:
	rm -f $(LIB_OBJ) $(CLI_OBJ) $(CLI_BIN) $(BPF_OBJ)

.PHONY: all clean cli check-asan check-libbpf bpf
