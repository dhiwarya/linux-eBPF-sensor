/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Shared definitions for all anyone-sensor BPF programs. */
#ifndef __ANYONE_SENSOR_COMMON_H
#define __ANYONE_SENSOR_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

enum event_type {
	EVENT_EXEC = 1,
};

/* Index into drop_count. One slot per reason so userspace can tell them apart. */
enum drop_reason {
	DROP_RINGBUF_FULL = 0,
	DROP_REASON_MAX,
};

/*
 * Common header at the start of every event in the ring buffer.
 * Clocks: timestamp and start_time are both CLOCK_BOOTTIME nanoseconds.
 * IDs (pid, tgid, ppid, uid, gid) are as seen from the initial namespaces.
 */
struct event {
	__u32 type;
	__u32 pid;       /* kernel thread ID */
	__u32 tgid;      /* process ID as shown by ps */
	__u32 ppid;      /* real_parent->tgid */
	__u32 uid;
	__u32 gid;
	__u64 timestamp;
	__u64 cgroup_id; /* cgroup v2 ID (inode number of the cgroup directory) */
	__u64 start_time;
};

/*
 * Types used only as locals are not emitted into BTF. Reference them from
 * globals so bpf2go can generate Go definitions for them.
 */
const enum event_type *_unused_event_type __attribute__((unused));
const enum drop_reason *_unused_drop_reason __attribute__((unused));
const struct event *_unused_event __attribute__((unused));

/* Per-CPU drop counters, summed across CPUs in userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_REASON_MAX);
	__type(key, __u32);
	__type(value, __u64);
} drop_count SEC(".maps");

/* 16 MiB. Must be a power of two and a multiple of the page size. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void count_drop(__u32 reason)
{
	__u64 *v = bpf_map_lookup_elem(&drop_count, &reason);

	if (v)
		(*v)++;
}

/* Fill the common header from the current task. */
static __always_inline void fill_header(struct event *e, __u32 type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->type = type;
	e->pid = (__u32)pid_tgid;
	e->tgid = pid_tgid >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)uid_gid;
	e->gid = uid_gid >> 32;
	e->timestamp = bpf_ktime_get_boot_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->start_time = BPF_CORE_READ(task, start_boottime);
}

#endif /* __ANYONE_SENSOR_COMMON_H */
