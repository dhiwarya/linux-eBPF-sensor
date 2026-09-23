// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

// Sizes of the C structs in bpf/. If these fail, a C struct changed and the
// bpf2go output must be regenerated.
const (
	headerSize        = 6*4 + 4*8
	wantExecEventSize = headerSize + 16 + 512 + 4 + 4 + 4096
	wantForkEventSize = headerSize + 16
	wantExitEventSize = headerSize + 16 + 4 + 4
)

func TestEventLayout(t *testing.T) {
	for name, tc := range map[string]struct {
		v    any
		want int
	}{
		"exec": {processExecEvent{}, wantExecEventSize},
		"fork": {processForkEvent{}, wantForkEventSize},
		"exit": {processExitEvent{}, wantExitEventSize},
	} {
		if got := binary.Size(tc.v); got != tc.want {
			t.Errorf("%s: binary.Size = %d, want %d", name, got, tc.want)
		}
	}
}

func header(t processEventType) processEvent {
	return processEvent{
		Type: uint32(t), Pid: 4242, Tgid: 4242, Ppid: 1200, Uid: 1000, Gid: 1000,
		Timestamp: 5_000_000_000, CgroupId: 8123, StartTime: 4_999_000_000, ParentStartTime: 1_000_000_000,
	}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rawExec builds an exec ring buffer record the way the BPF program would.
func rawExec(t *testing.T, argv []byte, truncated bool) []byte {
	t.Helper()
	r := processExecEvent{Hdr: header(processEventTypeEVENT_EXEC)}
	copy(r.Comm[:], "ls")
	copy(r.Filename[:], "/usr/bin/ls\x00stale-bytes-from-a-previous-record")
	n := copy(r.Argv[:], argv)
	r.ArgvLen = uint32(n)
	if truncated {
		r.ArgvTruncated = 1
	}
	// Garbage past argv_len must be ignored.
	if n < len(r.Argv) {
		r.Argv[n] = 'X'
	}
	return encode(t, &r)
}

func TestDecodeExecToJSON(t *testing.T) {
	boot := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	ev, err := decode(rawExec(t, []byte("ls\x00-la\x00/tmp\x00"), false), boot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"exec","time":"2026-09-23T00:00:05Z","timestamp_ns":5000000000,` +
		`"process":{"guid":"","pid":4242,"tid":4242,"uid":1000,"gid":1000,"cgroup_id":8123,` +
		`"start_time_ns":4999000000,"comm":"ls","image":"/usr/bin/ls","argv":["ls","-la","/tmp"]},` +
		`"parent":{"guid":"","pid":1200,"start_time_ns":1000000000,"known":false}}`
	if string(got) != want {
		t.Errorf("JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestDecodeExecTruncatedArgv(t *testing.T) {
	// A full 4 KiB buffer whose last argument was cut off by the kernel.
	long := "cat\x00" + strings.Repeat("a", 4096)
	ev, err := decode(rawExec(t, []byte(long), true), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Process.ArgvTruncated {
		t.Error("ArgvTruncated = false, want true")
	}
	want := []string{"cat", strings.Repeat("a", 4096-4)}
	if !reflect.DeepEqual(ev.Process.Argv, want) {
		t.Errorf("Argv = %d args, want 2 args with last of length %d", len(ev.Process.Argv), len(want[1]))
	}
}

func TestDecodeExecEmptyArgv(t *testing.T) {
	ev, err := decode(rawExec(t, nil, false), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Process.Argv == nil || len(ev.Process.Argv) != 0 {
		t.Errorf("Argv = %#v, want empty non-nil slice", ev.Process.Argv)
	}
}

func TestDecodeExecArgvLenOutOfRange(t *testing.T) {
	raw := rawExec(t, []byte("x\x00"), false)
	// Corrupt argv_len to a value larger than the buffer; decode must clamp, not panic.
	binary.LittleEndian.PutUint32(raw[headerSize+16+512:], 1<<20)
	if _, err := decode(raw, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeFork(t *testing.T) {
	r := processForkEvent{Hdr: header(processEventTypeEVENT_FORK)}
	copy(r.Comm[:], "bash")
	ev, err := decode(encode(t, &r), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != event.TypeFork || ev.Process.PID != 4242 || ev.Parent.PID != 1200 ||
		ev.Parent.StartTimeNs != 1_000_000_000 || ev.Process.Comm != "bash" {
		t.Errorf("unexpected fork event: %+v", ev)
	}
}

func TestDecodeExit(t *testing.T) {
	r := processExitEvent{Hdr: header(processEventTypeEVENT_EXIT), ExitCode: 3 << 8}
	copy(r.Comm[:], "false")
	ev, err := decode(encode(t, &r), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != event.TypeExit || ev.Exit == nil || ev.Exit.Code != 3 || ev.Exit.Signal != 0 {
		t.Errorf("unexpected exit event: %+v exit=%+v", ev, ev.Exit)
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := decode([]byte{1, 2}, time.Time{}); err == nil {
		t.Error("short record: want error")
	}
	raw := rawExec(t, nil, false)
	binary.LittleEndian.PutUint32(raw[0:], 99)
	if _, err := decode(raw, time.Time{}); err == nil {
		t.Error("unknown type: want error")
	}
	// A fork header on an exec-sized record must fail the size check.
	binary.LittleEndian.PutUint32(raw[0:], uint32(processEventTypeEVENT_FORK))
	if _, err := decode(raw, time.Time{}); err == nil {
		t.Error("size mismatch: want error")
	}
}
