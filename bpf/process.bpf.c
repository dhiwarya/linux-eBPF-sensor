// SPDX-License-Identifier: GPL-2.0 OR MIT
/* Process lifecycle hooks. Phase 1: exec only. */
#include "common.h"

#define MAX_FILENAME_LEN 512
#define MAX_ARGV_LEN 4096 /* must be a power of two (used as a mask) */

struct exec_event {
	struct event hdr;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[MAX_FILENAME_LEN];
	__u32 argv_len;           /* bytes valid in argv[] */
	__u8 argv_truncated;      /* original argv was longer than MAX_ARGV_LEN */
	__u8 argv_read_failed;    /* bpf_probe_read_user on argv failed */
	__u8 filename_truncated;  /* original filename was longer than MAX_FILENAME_LEN - 1 */
	__u8 _pad;
	__u8 argv[MAX_ARGV_LEN];  /* NUL-separated, exactly as in the process's memory */
};

const struct exec_event *_unused_exec_event __attribute__((unused));

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	struct exec_event *e;
	unsigned long arg_start, arg_end, len;
	__u32 loc, off, flen;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF_FULL);
		return 0;
	}

	fill_header(&e->hdr, EVENT_EXEC);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	/* __data_loc: low 16 bits = offset from ctx, high 16 bits = length incl. NUL. */
	loc = ctx->__data_loc_filename;
	off = loc & 0xFFFF;
	flen = loc >> 16;
	e->filename_truncated = flen > MAX_FILENAME_LEN;
	if (bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (void *)ctx + off) < 0)
		e->filename[0] = '\0';

	task = (struct task_struct *)bpf_get_current_task();
	arg_start = BPF_CORE_READ(task, mm, arg_start);
	arg_end = BPF_CORE_READ(task, mm, arg_end);
	len = arg_end > arg_start ? arg_end - arg_start : 0;

	e->argv_truncated = 0;
	e->argv_read_failed = 0;
	e->_pad = 0;
	if (len >= MAX_ARGV_LEN) {
		e->argv_truncated = len > MAX_ARGV_LEN;
		len = MAX_ARGV_LEN;
		if (bpf_probe_read_user(e->argv, MAX_ARGV_LEN, (void *)arg_start) < 0)
			goto read_failed;
	} else {
		/* The mask is a no-op (len < MAX_ARGV_LEN) but proves the bound to the verifier. */
		len &= MAX_ARGV_LEN - 1;
		if (bpf_probe_read_user(e->argv, len, (void *)arg_start) < 0)
			goto read_failed;
	}
	e->argv_len = len;
	bpf_ringbuf_submit(e, 0);
	return 0;

read_failed:
	e->argv_len = 0;
	e->argv_read_failed = 1;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
