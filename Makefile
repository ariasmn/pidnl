CC = clang
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address
RELEASE_CFLAGS = -O2 -Wall -Wextra \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector-strong \
	-fstack-clash-protection \
	-fcf-protection=full \
	-fPIE
RELEASE_LDFLAGS = -pie -s -Wl,-z,relro,-z,now -Wl,-z,noexecstack
ARCH_INCLUDE = /usr/include/$(shell $(CC) -print-multiarch 2>/dev/null || echo "$(shell uname -m)-linux-gnu")

LIBSRC = lib/src
CLI_OBJ = cli/main.o
CLI_BIN = cli/pidnl
BPF_SRC = lib/src/ratelimit.bpf.c
BPF_OBJ = $(LIBSRC)/ratelimit.bpf.o
BPF_SKEL = $(LIBSRC)/ratelimit_bpf.skel.h

GUI_OBJ = gui/main.o gui/processes.o gui/backend.o
GUI_BIN = gui/pidnl-gui
GUI_CFLAGS := $(shell pkg-config --cflags gtk4 libadwaita-1 gio-unix-2.0 2>/dev/null)
GUI_LDFLAGS := $(shell pkg-config --libs gtk4 libadwaita-1 gio-unix-2.0 2>/dev/null)

check-deps:
	@which clang >/dev/null 2>&1 || (echo "clang: MISSING" && exit 1)
	@which bpftool >/dev/null 2>&1 || (echo "bpftool: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libasan.so || (echo "libasan: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libbpf.so || (echo "libbpf: MISSING" && exit 1)
	@ldconfig -p 2>/dev/null | grep -q libelf.so || (echo "libelf: MISSING" && exit 1)

check-gui-deps:
	@pkg-config --exists gtk4 2>/dev/null || (echo "gtk4: MISSING" && exit 1)
	@pkg-config --exists libadwaita-1 2>/dev/null || (echo "libadwaita-1: MISSING" && exit 1)

dev: clean check-deps $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)

dev-gui: clean check-deps check-gui-deps $(BPF_SKEL) $(GUI_BIN)
	@G_SLICE=always-malloc LSAN_OPTIONS=suppressions=gui/lsan.supp $(GUI_BIN)

build: CFLAGS := $(RELEASE_CFLAGS)
build: LDFLAGS := $(RELEASE_LDFLAGS)
build: clean check-deps $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)

build-gui: CFLAGS := $(RELEASE_CFLAGS)
build-gui: LDFLAGS := $(RELEASE_LDFLAGS)
build-gui: clean check-deps check-gui-deps $(BPF_SKEL) $(GUI_BIN)

DIST_DIR = dist
NFPM := $(shell command -v nfpm 2>/dev/null || echo $(shell go env GOPATH 2>/dev/null)/bin/nfpm)
release: CFLAGS := $(RELEASE_CFLAGS)
release: LDFLAGS := $(RELEASE_LDFLAGS)
release: clean check-deps check-gui-deps $(BPF_SKEL) $(CLI_BIN) $(GUI_BIN)
	@command -v $(NFPM) >/dev/null 2>&1 || { echo "nfpm not found; install with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	@mkdir -p $(DIST_DIR)
	@for cfg in packaging/nfpm-cli.yaml packaging/nfpm-gui.yaml; do \
		$(NFPM) package --config $$cfg --packager rpm --target $(DIST_DIR)/; \
		$(NFPM) package --config $$cfg --packager deb --target $(DIST_DIR)/; \
	done

$(BPF_SKEL): $(BPF_OBJ)
	@bpftool gen skeleton $< > $@

$(BPF_OBJ): $(BPF_SRC)
	@$(CC) -O2 -target bpf -g -I$(ARCH_INCLUDE) -c $< -o $@

$(CLI_BIN): $(LIBSRC)/discovery.o $(LIBSRC)/ratelimit.o $(LIBSRC)/monitor.o $(CLI_OBJ)
	@$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -L/usr/lib64 -lbpf -lelf -lcgroup

$(GUI_BIN): $(GUI_OBJ) $(LIBSRC)/discovery.o $(LIBSRC)/ratelimit.o $(LIBSRC)/monitor.o | $(BPF_SKEL)
	@$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(GUI_LDFLAGS) -lbpf -lelf -lcgroup

$(LIBSRC)/ratelimit.o: $(BPF_SKEL)

$(LIBSRC)/%.o: $(LIBSRC)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

cli/%.o: cli/%.c
	@$(CC) $(CFLAGS) -I$(LIBSRC) -c $< -o $@

gui/%.o: gui/%.c
	@$(CC) $(CFLAGS) $(GUI_CFLAGS) -I$(LIBSRC) -c $< -o $@

clean:
	@rm -f $(LIBSRC)/*.o cli/*.o gui/*.o $(CLI_BIN) $(GUI_BIN) $(BPF_OBJ) $(BPF_SKEL) 2>/dev/null

lint:
	@clang-format --dry-run --Werror cli/*.c gui/*.c lib/src/*.c

CONTAINER_CMD := $(shell which docker 2>/dev/null || which podman 2>/dev/null || echo "")
CONTAINER_IMAGE := ubuntu:26.04

test:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "error: tests must be run as root (try: sudo make test)"; \
		exit 1; \
	fi
	@if [ -z "$(CONTAINER_CMD)" ]; then \
		echo "error: docker or podman is required to run tests"; \
		exit 1; \
	fi
	@echo "Running tests in $(CONTAINER_IMAGE) via $(CONTAINER_CMD)..."
	@$(CONTAINER_CMD) run --privileged --cgroupns=host --rm \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		$(CONTAINER_IMAGE) \
		bash -c ' \
			set -e; \
			export DEBIAN_FRONTEND=noninteractive; \
			apt-get update >/dev/null 2>&1; \
			apt-get install -y \
				clang \
				bpftool \
				libbpf-dev \
				libnl-3-dev \
				libnl-route-3-dev \
				libelf-dev \
				libcgroup-dev \
				netcat-openbsd \
				make >/dev/null 2>&1; \
			make dev; \
			bash tests/run.sh \
		'

.PHONY: dev dev-gui build build-gui release clean check-deps check-gui-deps lint test
