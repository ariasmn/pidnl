CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address

# Directories
LIBSRC = lib/src

# Include paths
INCLUDES = -I$(LIBSRC)

# Library
LIB_OBJ = $(LIBSRC)/strait.o

# CLI
CLI_OBJ = cli/main.o
CLI_BIN = cli/strait

.PHONY: all clean cli check-asan

all: check-asan cli

check-asan:
	@echo "int main(void){return 0;}" | $(CC) -fsanitize=address -x c - -o /dev/null 2>/dev/null || \
		(echo "Error: libasan not found" && exit 1)

$(LIBSRC)/%.o: $(LIBSRC)/%.c $(LIBSRC)/%.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

cli/%.o: cli/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

cli: $(CLI_BIN)

$(CLI_BIN): $(LIB_OBJ) $(CLI_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(LIB_OBJ) $(CLI_OBJ) $(CLI_BIN)
