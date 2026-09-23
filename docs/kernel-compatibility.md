<!-- SPDX-License-Identifier: Apache-2.0 -->
# Kernel compatibility

Regenerate with `sudo scripts/feature-report.sh`. Add a section per kernel tested.

## Notes

- **BPF-LSM:** the `lsm` program type is compiled in, but `bpf` is not in the active LSM list on stock Ubuntu, so `lsm/*` programs load but never run. Enabling it needs a boot parameter (`lsm=...,bpf`), which the sensor must not require. The file hooks (Phase 3) therefore default to fentry on stock Ubuntu.
- **cgroup v2** (`cgroup2fs`) with the Docker `systemd` cgroup driver: container cgroups are `/sys/fs/cgroup/system.slice/docker-<id>.scope`.
- `bpf_ktime_get_boot_ns` and ring buffers need kernel 5.8+, so Ubuntu 20.04 (5.4) is not supported.

## Ubuntu 24.04, arm64 (dev VM)

Generated 2026-09-23T08:07:17Z on `anyone-sensor`.

| Feature | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS |
| Kernel | `6.8.0-139-generic` |
| Arch | `aarch64` |
| BTF (`/sys/kernel/btf/vmlinux`) | yes |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor` |
| BPF LSM active | no |
| cgroup fs on /sys/fs/cgroup | `cgroup2fs` |
| unprivileged_bpf_disabled | `2` |
| bpftool | `bpftool v7.4.0` |
| map: ringbuf | yes |
| prog: tracepoint | yes |
| prog: tracing (fentry/fexit) | yes |
| prog: lsm | yes |
| prog: kprobe | yes |
| helper: bpf_d_path (tracing) | yes |
| helper: bpf_ktime_get_boot_ns | yes |
| Container runtime | docker 29.1.3 |
| Docker cgroup driver | `systemd` |
