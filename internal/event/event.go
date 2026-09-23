// SPDX-License-Identifier: Apache-2.0

// Package event defines the decoded, userspace form of sensor events.
package event

import (
	"bytes"
	"time"
)

// Type is the kind of event.
type Type string

const (
	TypeExec Type = "exec"
	TypeFork Type = "fork"
	TypeExit Type = "exit"
)

// Event is one process event. The loader fills the kernel facts; proctable and
// the container resolver fill GUIDs, parent details and container metadata.
type Event struct {
	Type        Type       `json:"type"`
	Time        time.Time  `json:"time"`
	TimestampNs uint64     `json:"timestamp_ns"` // CLOCK_BOOTTIME
	Process     Process    `json:"process"`
	Parent      Parent     `json:"parent"`
	Container   *Container `json:"container,omitempty"`
	Exit        *Exit      `json:"exit,omitempty"`
}

// Process is the process the event is about (for fork: the child).
type Process struct {
	GUID              string   `json:"guid"`
	PID               uint32   `json:"pid"` // tgid
	TID               uint32   `json:"tid"` // kernel thread that triggered the event
	UID               uint32   `json:"uid"`
	GID               uint32   `json:"gid"`
	CgroupID          uint64   `json:"cgroup_id"`
	StartTimeNs       uint64   `json:"start_time_ns"` // CLOCK_BOOTTIME
	Comm              string   `json:"comm"`
	Image             string   `json:"image,omitempty"`
	Argv              []string `json:"argv,omitempty"`
	FilenameTruncated bool     `json:"filename_truncated,omitempty"`
	ArgvTruncated     bool     `json:"argv_truncated,omitempty"`
	ArgvReadFailed    bool     `json:"argv_read_failed,omitempty"`
}

// Parent is the process's real parent at the time of the event.
type Parent struct {
	GUID        string   `json:"guid"`
	PID         uint32   `json:"pid"`
	StartTimeNs uint64   `json:"start_time_ns"`
	Image       string   `json:"image,omitempty"`
	Argv        []string `json:"argv,omitempty"`
	// Known is false when proctable has no record of the parent, e.g. it
	// exited before the sensor started and could not be read from /proc.
	Known bool `json:"known"`
	// External is true when the parent is outside the target container, e.g.
	// containerd-shim for `docker exec` processes.
	External bool `json:"external,omitempty"`
}

// Container identifies the container the process runs in.
type Container struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
}

// Exit is set on exit events.
type Exit struct {
	Code   uint32 `json:"code"`             // exit status (0-255) when the process exited normally
	Signal uint32 `json:"signal,omitempty"` // terminating signal, 0 if none
	Raw    uint32 `json:"raw"`              // kernel exit_code: (status << 8) | signal
}

// ExitFromRaw decodes the kernel's wait(2)-style exit_code.
func ExitFromRaw(raw uint32) *Exit {
	return &Exit{Code: (raw >> 8) & 0xff, Signal: raw & 0x7f, Raw: raw}
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
