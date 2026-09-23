#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Print the kernel features anyone-sensor depends on. Output is Markdown so it
# can be pasted into docs/kernel-compatibility.md or a bug report.
# Run as root for complete bpftool results: sudo scripts/feature-report.sh
set -u

have() { command -v "$1" >/dev/null 2>&1; }
yesno() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

BPFTOOL=${BPFTOOL:-bpftool}
probe=""
if have "$BPFTOOL"; then
	probe=$("$BPFTOOL" feature probe kernel 2>/dev/null || true)
fi
probe_has() { grep -q "$1" <<<"$probe" && echo yes || echo no; }

echo "# Kernel feature report"
echo
echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) on \`$(hostname)\`."
echo
echo "| Feature | Value |"
echo "|---|---|"
echo "| OS | $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}") |"
echo "| Kernel | \`$(uname -r)\` |"
echo "| Arch | \`$(uname -m)\` |"
echo "| BTF (\`/sys/kernel/btf/vmlinux\`) | $(yesno test -r /sys/kernel/btf/vmlinux) |"
echo "| Active LSMs | \`$(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)\` |"
echo "| BPF LSM active | $(grep -qw bpf /sys/kernel/security/lsm 2>/dev/null && echo yes || echo no) |"
echo "| cgroup fs on /sys/fs/cgroup | \`$(stat -fc %T /sys/fs/cgroup 2>/dev/null)\` |"
echo "| unprivileged_bpf_disabled | \`$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)\` |"

if [ -n "$probe" ]; then
	echo "| bpftool | \`$("$BPFTOOL" version 2>/dev/null | head -1)\` |"
	echo "| map: ringbuf | $(probe_has 'map_type ringbuf is available') |"
	echo "| prog: tracepoint | $(probe_has 'program_type tracepoint is available') |"
	echo "| prog: tracing (fentry/fexit) | $(probe_has 'program_type tracing is available') |"
	echo "| prog: lsm | $(probe_has 'program_type lsm is available') |"
	echo "| prog: kprobe | $(probe_has 'program_type kprobe is available') |"
	echo "| helper: bpf_d_path (tracing) | $(awk '/program type tracing/,/^$/' <<<"$probe" | grep -q 'bpf_d_path' && echo yes || echo no) |"
	echo "| helper: bpf_ktime_get_boot_ns | $(probe_has 'bpf_ktime_get_boot_ns') |"
else
	echo "| bpftool | not available or not root: feature probes skipped |"
fi

runtime=""
have docker && docker info >/dev/null 2>&1 && runtime="docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
[ -z "$runtime" ] && have containerd && runtime="containerd $(containerd --version 2>/dev/null | awk '{print $3}')"
[ -z "$runtime" ] && have docker && runtime="docker (daemon not reachable)"
echo "| Container runtime | ${runtime:-none found} |"
echo "| Docker cgroup driver | \`$(have docker && docker info --format '{{.CgroupDriver}}' 2>/dev/null)\` |"
