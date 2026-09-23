// SPDX-License-Identifier: Apache-2.0

// Package event defines the decoded, userspace form of sensor events.
package event

import (
	"bytes"
	"time"
)

// Exec is a successful execve observed by the sched_process_exec tracepoint.
type Exec struct {
	Type              string    `json:"type"`
	Time              time.Time `json:"time"`
	TimestampNs       uint64    `json:"timestamp_ns"` // CLOCK_BOOTTIME
	PID               uint32    `json:"pid"`          // kernel thread ID
	TGID              uint32    `json:"tgid"`         // process ID
	PPID              uint32    `json:"ppid"`
	UID               uint32    `json:"uid"`
	GID               uint32    `json:"gid"`
	CgroupID          uint64    `json:"cgroup_id"`
	StartTimeNs       uint64    `json:"start_time_ns"` // CLOCK_BOOTTIME
	Comm              string    `json:"comm"`
	Filename          string    `json:"filename"`
	FilenameTruncated bool      `json:"filename_truncated"`
	Argv              []string  `json:"argv"`
	ArgvTruncated     bool      `json:"argv_truncated"`
	ArgvReadFailed    bool      `json:"argv_read_failed,omitempty"`
}

// SplitArgv splits a NUL-separated argv buffer, as found between mm->arg_start
// and mm->arg_end, into its arguments. The terminating NUL of the last argument
// is dropped; empty arguments in between are kept. A truncated buffer ends in a
// partial argument without a NUL, which is returned as-is.
func SplitArgv(b []byte) []string {
	b = bytes.TrimSuffix(b, []byte{0})
	if len(b) == 0 {
		return []string{}
	}
	parts := bytes.Split(b, []byte{0})
	args := make([]string, len(parts))
	for i, p := range parts {
		args[i] = string(p)
	}
	return args
}

// CString returns the bytes of b up to the first NUL.
func CString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
