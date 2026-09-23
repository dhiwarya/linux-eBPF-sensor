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
	EVENT_FORK = 2,
	EVENT_EXIT = 3,
};

/* Index into drop_count. One slot per reason so userspace can tell them apart. */
enum drop_reason {
	DROP_RINGBUF_FULL = 0,
	DROP_REASON_MAX,
};

/*
 * Common header at the start of every event in the ring buffer. It describes
 * the process the event is about (for fork: the child).
 * Clocks: timestamp and the start times are CLOCK_BOOTTIME nanoseconds. The
 * start times are the thread-group leader's, i.e. the process start time that
 * /proc/<pid>/stat reports, so userspace can derive the same process GUID from
 * kernel events and from /proc.
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
	__u64 parent_start_time;
};

/*
 * Types used only as locals are not emitted into BTF. Reference them from
 * globals so bpf2go can generate Go definitions for them.
 */
const enum event_type *_unused_event_type __attribute__((unused));
const enum drop_reason *_unused_drop_reason __attribute__((unused));
const struct event *_unused_event __attribute__((unused));

/* Capture every cgroup instead of only target_cgroups. Set by the loader. */
volatile const bool mode_host = false;

/* cgroup v2 IDs of the target container. Written by userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} target_cgroups SEC(".maps");

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

static __always_inline __u64 task_cgroup_id(struct task_struct *task)
{
	return BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
}

/* Every program calls this first, before reserving ring buffer space. */
static __always_inline bool should_capture(__u64 cgroup_id)
{
	if (mode_host)
		return true;
	return bpf_map_lookup_elem(&target_cgroups, &cgroup_id) != NULL;
}

/* Fill the common header from task, whose cgroup ID the caller already read. */
static __always_inline void fill_header(struct event *e, __u32 type,
					struct task_struct *task, __u64 cgroup_id)
{
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);

	e->type = type;
	e->pid = BPF_CORE_READ(task, pid);
	e->tgid = BPF_CORE_READ(task, tgid);
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->uid = BPF_CORE_READ(task, cred, uid.val);
	e->gid = BPF_CORE_READ(task, cred, gid.val);
	e->timestamp = bpf_ktime_get_boot_ns();
	e->cgroup_id = cgroup_id;
	e->start_time = BPF_CORE_READ(task, group_leader, start_boottime);
	e->parent_start_time = BPF_CORE_READ(parent, group_leader, start_boottime);
}

#endif /* __ANYONE_SENSOR_COMMON_H */
