/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Per-architecture vmlinux.h selector. bpf2go defines __TARGET_ARCH_<arch>
 * for each -target it builds.
 *
 * vmlinux_arm64.h: dumped from the dev VM (make vmlinux).
 * vmlinux_amd64.h: dumped from the BTF of Ubuntu's 6.8.0-139 amd64 kernel
 *                  package (cannot be dumped on an arm64 host; see
 *                  docs/development.md). CO-RE relocates field offsets against
 *                  the running kernel's BTF at load time.
 */
#if defined(__TARGET_ARCH_x86)
#include "vmlinux_amd64.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_arm64.h"
#else
#error "unsupported target architecture"
#endif
