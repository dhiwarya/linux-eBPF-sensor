// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

// decodeExec turns a raw ring buffer record into an event.Exec. boot is the
// wall-clock time of CLOCK_BOOTTIME zero, used to convert kernel timestamps.
func decodeExec(raw []byte, boot time.Time) (event.Exec, error) {
	var r processExecEvent
	if len(raw) != binary.Size(r) {
		return event.Exec{}, fmt.Errorf("exec event: got %d bytes, want %d", len(raw), binary.Size(r))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
		return event.Exec{}, fmt.Errorf("exec event: %w", err)
	}
	if r.Hdr.Type != uint32(processEventTypeEVENT_EXEC) {
		return event.Exec{}, fmt.Errorf("exec event: unexpected type %d", r.Hdr.Type)
	}

	argvLen := min(int(r.ArgvLen), len(r.Argv))
	return event.Exec{
		Type:              "exec",
		Time:              boot.Add(time.Duration(r.Hdr.Timestamp)),
		TimestampNs:       r.Hdr.Timestamp,
		PID:               r.Hdr.Pid,
		TGID:              r.Hdr.Tgid,
		PPID:              r.Hdr.Ppid,
		UID:               r.Hdr.Uid,
		GID:               r.Hdr.Gid,
		CgroupID:          r.Hdr.CgroupId,
		StartTimeNs:       r.Hdr.StartTime,
		Comm:              event.CString(r.Comm[:]),
		Filename:          event.CString(r.Filename[:]),
		FilenameTruncated: r.FilenameTruncated != 0,
		Argv:              event.SplitArgv(r.Argv[:argvLen]),
		ArgvTruncated:     r.ArgvTruncated != 0,
		ArgvReadFailed:    r.ArgvReadFailed != 0,
	}, nil
}
