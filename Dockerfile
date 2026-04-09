FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    make \
    build-essential \
    wget \
    libbpf-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    libelf-dev \
    libcgroup-dev \
    libssl-dev \
    linux-tools-generic \
    linux-tools-common \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 ships a broken bpftool. Rebuild from kernel source.
RUN KERNEL_VERSION=$(uname -r) && \
    KERNEL_MAJOR_MINOR=$(echo "$KERNEL_VERSION" | awk -F'[.-]' '{print $1 "." $2}') && \
    BUILD_DIR="/usr/lib/linux-tools/${KERNEL_VERSION}" && \
    cd /tmp && \
    wget -q "https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_MAJOR_MINOR}.tar.xz" && \
    tar -xf "linux-${KERNEL_MAJOR_MINOR}.tar.xz" && \
    cd "linux-${KERNEL_MAJOR_MINOR}/tools/bpf/bpftool" && \
    make -j$(nproc) bootstrap && \
    mkdir -p "${BUILD_DIR}" && \
    install -m 0755 bootstrap/bpftool "${BUILD_DIR}/bpftool" && \
    ln -sf "${BUILD_DIR}/bpftool" /usr/local/bin/bpftool && \
    rm -rf /tmp/linux-*

COPY . /src
WORKDIR /src

RUN make dev

CMD ["bash", "tests/run.sh"]
