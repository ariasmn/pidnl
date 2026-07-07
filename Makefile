CC = clang
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address
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

CONTAINER_CMD := $(shell which podman 2>/dev/null || which docker 2>/dev/null || echo "")
TEST_IMAGE := ubuntu:26.04

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "0.0.0-dev")
PACKAGER ?= rpm deb
NFPM := $(shell command -v nfpm 2>/dev/null || echo $(shell go env GOPATH 2>/dev/null)/bin/nfpm)
DIST_DIR = dist

RPM_IMAGE  := fedora:44
DEB_IMAGE  := debian:13
ARCH_IMAGE := archlinux:latest

RELEASE_CFLAGS = -O2 -Wall -Wextra \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector-strong \
	-fstack-clash-protection \
	-fcf-protection=full \
	-fPIE
RELEASE_LDFLAGS = -pie -s -Wl,-z,relro,-z,now -Wl,-z,noexecstack

# Development targets
check-deps:
	@command -v clang >/dev/null 2>&1 || (echo "clang: MISSING" && exit 1)
	@command -v bpftool >/dev/null 2>&1 || (echo "bpftool: MISSING" && exit 1)
	@command -v pkg-config >/dev/null 2>&1 || (echo "pkg-config: MISSING" && exit 1)
	@pkg-config --exists libbpf 2>/dev/null || (echo "libbpf: MISSING" && exit 1)
	@pkg-config --exists libelf 2>/dev/null || (echo "libelf: MISSING" && exit 1)
	@pkg-config --exists libcgroup 2>/dev/null || (echo "libcgroup: MISSING" && exit 1)

check-dev-deps: check-deps
	@ldconfig -p 2>/dev/null | grep -q libasan.so || (echo "libasan: MISSING" && exit 1)

check-gui-deps:
	@pkg-config --exists gtk4 2>/dev/null || (echo "gtk4: MISSING" && exit 1)
	@pkg-config --exists libadwaita-1 2>/dev/null || (echo "libadwaita-1: MISSING" && exit 1)

dev: clean check-dev-deps $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)

dev-gui: clean check-dev-deps check-gui-deps $(BPF_SKEL) $(GUI_BIN)
	@G_SLICE=always-malloc LSAN_OPTIONS=suppressions=gui/lsan.supp $(GUI_BIN)

build: CFLAGS := $(RELEASE_CFLAGS)
build: LDFLAGS := $(RELEASE_LDFLAGS)
build: clean check-deps $(BPF_SKEL) $(BPF_OBJ) $(CLI_BIN)

build-gui: CFLAGS := $(RELEASE_CFLAGS)
build-gui: LDFLAGS := $(RELEASE_LDFLAGS)
build-gui: clean check-deps check-gui-deps $(BPF_SKEL) $(GUI_BIN)

lint:
	@clang-format --dry-run --Werror cli/*.c gui/*.c lib/src/*.c

# Release targets
release: CFLAGS := $(RELEASE_CFLAGS)
release: LDFLAGS := $(RELEASE_LDFLAGS)
release: clean check-deps check-gui-deps $(BPF_SKEL) $(CLI_BIN) $(GUI_BIN)
	@command -v $(NFPM) >/dev/null 2>&1 || { echo "nfpm not found; install with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	@mkdir -p $(DIST_DIR)
	@for cfg in packaging/nfpm-cli.yaml packaging/nfpm-gui.yaml; do \
		for p in $(PACKAGER); do \
			case "$$p" in \
				archlinux) v="$$(echo '$(VERSION)' | sed 's/-/./g')" ;; \
				*) v="$(VERSION)" ;; \
			esac; \
			PIDNL_VERSION="$$v" $(NFPM) package --config $$cfg --packager $$p --target $(DIST_DIR)/; \
		done; \
	done

container-rpm:
	@if [ -z "$(CONTAINER_CMD)" ]; then echo "error: podman or docker required"; exit 1; fi
	$(CONTAINER_CMD) run --rm -v "$(CURDIR):/workspace:Z" -w /workspace $(RPM_IMAGE) \
		bash -c 'set -e; \
			dnf install -y --setopt=install_weak_deps=False clang bpftool make \
				libbpf-devel elfutils-libelf-devel gtk4-devel libadwaita-devel \
				libcgroup-devel golang >/dev/null; \
			export PATH="$$PATH:$$(go env GOPATH)/bin"; \
			command -v nfpm >/dev/null 2>&1 || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest; \
			make release PACKAGER=rpm VERSION="$(VERSION)"'

container-deb:
	@if [ -z "$(CONTAINER_CMD)" ]; then echo "error: podman or docker required"; exit 1; fi
	$(CONTAINER_CMD) run --rm -v "$(CURDIR):/workspace:Z" -w /workspace $(DEB_IMAGE) \
		bash -c 'set -e; \
			export DEBIAN_FRONTEND=noninteractive; \
			apt-get update >/dev/null; \
			apt-get install -y clang bpftool make libbpf-dev libelf-dev \
				libcgroup-dev libgtk-4-dev libadwaita-1-dev golang-go >/dev/null; \
			export PATH="$$PATH:$$(go env GOPATH)/bin"; \
			command -v nfpm >/dev/null 2>&1 || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest; \
			make release PACKAGER=deb VERSION="$(VERSION)"'

container-arch:
	@if [ -z "$(CONTAINER_CMD)" ]; then echo "error: podman or docker required"; exit 1; fi
	$(CONTAINER_CMD) run --rm -v "$(CURDIR):/workspace:Z" -w /workspace $(ARCH_IMAGE) \
		bash -c 'set -e; \
			pacman-key --init >/dev/null 2>&1 || true; \
			pacman-key --populate archlinux >/dev/null 2>&1 || true; \
			pacman -Sy --noconfirm base-devel clang bpf make libbpf elfutils \
				gtk4 libadwaita go >/dev/null; \
			cd /tmp; \
			curl -fsSL -o libcgroup.tar.gz https://github.com/libcgroup/libcgroup/releases/download/v3.2.0/libcgroup-3.2.0.tar.gz; \
			tar -xzf libcgroup.tar.gz; \
			cd libcgroup-3.2.0; \
			./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --sbindir=/usr/bin --enable-opaque-hierarchy=name=systemd >/dev/null; \
			make -j$$(nproc) >/dev/null; \
			make install >/dev/null; \
			ldconfig; \
			cd /workspace; \
			export PATH="$$PATH:$$(go env GOPATH)/bin"; \
			command -v nfpm >/dev/null 2>&1 || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest; \
			make release PACKAGER=archlinux VERSION="$(VERSION)"'

# Test target
test:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "error: tests must be run as root (try: sudo make test)"; \
		exit 1; \
	fi
	@if [ -z "$(CONTAINER_CMD)" ]; then \
		echo "error: docker or podman is required to run tests"; \
		exit 1; \
	fi
	@echo "Running tests in $(TEST_IMAGE) via $(CONTAINER_CMD)..."
	@$(CONTAINER_CMD) run --privileged --cgroupns=host --rm \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		$(TEST_IMAGE) \
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

# Cleanup
clean:
	@rm -f $(LIBSRC)/*.o cli/*.o gui/*.o $(CLI_BIN) $(GUI_BIN) $(BPF_OBJ) $(BPF_SKEL) 2>/dev/null

# Build rules
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

.PHONY: dev dev-gui build build-gui release container-rpm container-deb container-arch clean check-deps check-dev-deps check-gui-deps lint test
