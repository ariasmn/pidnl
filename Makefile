CC = clang
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address

LIBSRC = lib/src
CLI_OBJ = cli/main.o
CLI_BIN = cli/strait
BPF_SRC = lib/src/ratelimit.bpf.c
BPF_OBJ = $(LIBSRC)/ratelimit.bpf.o

all: check-asan $(BPF_OBJ) $(CLI_BIN)

check-asan:
	@echo "int main(void){return 0;}" | $(CC) -fsanitize=address -x c - -o /dev/null 2>/dev/null || \
		(echo "Error: libasan not found" && exit 1)

$(BPF_OBJ): $(BPF_SRC)
	$(CC) -O2 -target bpf -g -c $< -o $@

$(CLI_BIN): $(LIBSRC)/discovery.o $(LIBSRC)/ratelimit.o $(CLI_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -L/usr/lib64 -lnl-3 -lnl-route-3 -lbpf -lelf -lz

$(LIBSRC)/%.o: $(LIBSRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

cli/%.o: cli/%.c
	$(CC) $(CFLAGS) -I$(LIBSRC) -c $< -o $@

clean:
	rm -f $(LIBSRC)/*.o cli/*.o $(CLI_BIN) $(BPF_OBJ)

.PHONY: all clean check-asan
