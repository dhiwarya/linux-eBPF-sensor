<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development

## Pinned versions

| Component | Version |
|---|---|
| Go | 1.26.2 |
| github.com/cilium/ebpf (+ bpf2go) | v0.22.0 |
| clang/llvm | Ubuntu 24.04 default (18) |
| OCSF schema | 1.3.0 |

## Dev VM (macOS host)

eBPF needs a Linux kernel, so development runs in a Multipass VM (Ubuntu 24.04, arm64, kernel 6.8)
with the repo mounted:

```sh
multipass launch 24.04 --name anyone-sensor --cpus 4 --memory 8G --disk 30G
multipass mount . anyone-sensor:/home/ubuntu/linux-sensor
multipass shell anyone-sensor
```

Inside the VM:

```sh
sudo apt-get install -y clang llvm libbpf-dev make linux-tools-common linux-tools-$(uname -r) bpftrace docker.io
# Go from go.dev (the apt version is too old)
```

## Build

```sh
make vmlinux    # dump bpf/headers/vmlinux_<arch>.h for the running kernel
make generate   # clang + bpf2go -> internal/loader/process_{x86,arm64}_bpfel.{go,o}
make build      # CGO_ENABLED=0 go build; no clang needed
make test
make run        # sudo ./anyone-sensor
```

The bpf2go output is committed, so `go build` works on machines without clang, and
`GOARCH=amd64|arm64 go build` cross-compiles.

### vmlinux.h per architecture

`bpf/headers/vmlinux.h` includes `vmlinux_amd64.h` or `vmlinux_arm64.h` depending on the
`__TARGET_ARCH_*` define that bpf2go sets for each target. The arm64 header is dumped from the dev
VM. The amd64 header cannot be dumped on an arm64 host, so it is dumped from the BTF of the Ubuntu
24.04 amd64 kernel package instead:

```sh
curl -LO http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-6.8.0-139-generic_6.8.0-139.139_amd64.deb
dpkg-deb -x linux-image-unsigned-6.8.0-139-generic_6.8.0-139.139_amd64.deb pkg
curl -L -o extract-vmlinux https://raw.githubusercontent.com/torvalds/linux/v6.8/scripts/extract-vmlinux
sh extract-vmlinux pkg/boot/vmlinuz-6.8.0-139-generic > vmlinux
bpftool btf dump file vmlinux format c   # -> bpf/headers/vmlinux_amd64.h (after the SPDX lines)
```

Every kernel read goes through CO-RE (`BPF_CORE_READ`), which relocates field offsets against the
running kernel's BTF at load time, so one header per architecture covers other kernel versions.

Headers from kernels 6.18 and later (for example `libbpf/vmlinux.h`'s `vmlinux_6.19.h`) do not
compile with plain clang: those kernels are built with `-fms-extensions`, and their BTF dump contains
anonymous tagged struct members such as `struct ns_tree;`.

## Running

```sh
sudo ./anyone-sensor -container my-app          # one container by name (default mode)
sudo ./anyone-sensor -container-id 576afc71     # by ID prefix
sudo ./anyone-sensor -container-label app=web   # by label (must match exactly one)
sudo ./anyone-sensor -mode host                 # everything on the host
sudo ./anyone-sensor -container my-app -stats-interval 10s
make e2e                                        # test/e2e/*.sh as root
```

Each line on stdout is one event (`exec`, `fork` or `exit`) with `process`, `parent` and
`container` objects. `process.guid` is stable for the life of a process and across sensor restarts.
`parent.external` marks a parent outside the target container: `docker exec` processes are
children of `containerd-shim`, not of the container's init.

## Debugging

- `bpf_printk("...")` in BPF code, then `sudo cat /sys/kernel/tracing/trace_pipe`.
- `sudo bpftool prog list` / `sudo bpftool prog show name handle_exec`.
- `sudo bpftool map dump name drop_count` shows per-CPU drop counters.
- Verifier failures: `loader.Load` prints the full verifier log (`%+v` of `ebpf.VerifierError`).
