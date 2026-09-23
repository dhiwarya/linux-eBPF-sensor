// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

// decode turns a raw ring buffer record into an event.Event. boot is the
// wall-clock time of CLOCK_BOOTTIME zero, used to convert kernel timestamps.
// GUIDs, parent details and container metadata are left for enrichment.
func decode(raw []byte, boot time.Time) (event.Event, error) {
	if len(raw) < 4 {
		return event.Event{}, fmt.Errorf("record too short: %d bytes", len(raw))
	}
	switch t := processEventType(binary.LittleEndian.Uint32(raw)); t {
	case processEventTypeEVENT_EXEC:
		var r processExecEvent
		if err := read(raw, &r); err != nil {
			return event.Event{}, fmt.Errorf("exec event: %w", err)
		}
		ev := fromHeader(event.TypeExec, &r.Hdr, r.Comm[:], boot)
		argvLen := min(int(r.ArgvLen), len(r.Argv))
		ev.Process.Image = event.CString(r.Filename[:])
		ev.Process.Argv = event.SplitArgv(r.Argv[:argvLen])
		ev.Process.FilenameTruncated = r.FilenameTruncated != 0
		ev.Process.ArgvTruncated = r.ArgvTruncated != 0
		ev.Process.ArgvReadFailed = r.ArgvReadFailed != 0
		return ev, nil
	case processEventTypeEVENT_FORK:
		var r processForkEvent
		if err := read(raw, &r); err != nil {
			return event.Event{}, fmt.Errorf("fork event: %w", err)
		}
		return fromHeader(event.TypeFork, &r.Hdr, r.Comm[:], boot), nil
	case processEventTypeEVENT_EXIT:
		var r processExitEvent
		if err := read(raw, &r); err != nil {
			return event.Event{}, fmt.Errorf("exit event: %w", err)
		}
		ev := fromHeader(event.TypeExit, &r.Hdr, r.Comm[:], boot)
		ev.Exit = event.ExitFromRaw(r.ExitCode)
		return ev, nil
	default:
		return event.Event{}, fmt.Errorf("unknown event type %d", t)
	}
}

// read decodes raw into the fixed-size struct v, requiring an exact size match.
func read(raw []byte, v any) error {
	if want := binary.Size(v); len(raw) != want {
		return fmt.Errorf("got %d bytes, want %d", len(raw), want)
	}
	return binary.Read(bytes.NewReader(raw), binary.LittleEndian, v)
}

func fromHeader(t event.Type, h *processEvent, comm []byte, boot time.Time) event.Event {
	return event.Event{
		Type:        t,
		Time:        boot.Add(time.Duration(h.Timestamp)),
		TimestampNs: h.Timestamp,
		Process: event.Process{
			PID:         h.Tgid,
			TID:         h.Pid,
			UID:         h.Uid,
			GID:         h.Gid,
			CgroupID:    h.CgroupId,
			StartTimeNs: h.StartTime,
			Comm:        event.CString(comm),
		},
		Parent: event.Parent{
			PID:         h.Ppid,
			StartTimeNs: h.ParentStartTime,
		},
	}
}
