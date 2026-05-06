# strait

## Dependencies

- **libcgroup >= 3.0** (required for cgroup v2 empty cgroup support)
- clang
- bpftool
- libbpf
- libnl-3
- libnl-route-3
- libelf

## Build

```bash
make dev
```

## Run tests

Tests require root privileges and a kernel with cgroup v2 and BPF support:

```bash
sudo make test
```

## Distribution

`strait` is a C/BPF application. Unlike Go, you cannot compile a single static
binary and expect it to run on every Linux distribution. The binary has runtime
dependencies on:

- The host kernel (BPF cgroup helpers must be available)
- Shared libraries (`libbpf`, `libcgroup`, `libnl-3`, etc.)
- A mounted cgroup v2 hierarchy

Because of these dependencies, the recommended ways to distribute are:

1. **Source distribution** — Provide build instructions and let users compile on
their machine. This is the simplest approach for a small project.

2. **Package manager packages** — Build `.deb` (Debian/Ubuntu), `.rpm`
(Fedora/RHEL), or PKGBUILD (Arch) packages that declare the correct runtime
dependencies. This is the standard way C tools are distributed on Linux.

3. **Container image** — Ship the binary together with all required libraries in
an OCI image. Users run it with `--privileged` so the container can access the
host's cgroup and BPF subsystems.

4. **Static linking** — In theory you could statically link `libbpf`,
`libcgroup`, `libnl`, and `libelf`. In practice this is fragile for BPF tools
because libbpf needs to match kernel features, and fully static linking against
glibc has well-known limitations. It is usually not worth the effort compared to
option 2.
