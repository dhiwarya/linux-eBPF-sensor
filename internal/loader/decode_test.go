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
)

// wantExecEventSize is sizeof(struct exec_event) in bpf/process.bpf.c. If this
// fails, the C struct changed and the bpf2go output must be regenerated.
const wantExecEventSize = 48 + 16 + 512 + 4 + 4 + 4096

func TestExecEventLayout(t *testing.T) {
	if got := binary.Size(processExecEvent{}); got != wantExecEventSize {
		t.Fatalf("binary.Size(processExecEvent) = %d, want %d", got, wantExecEventSize)
	}
}

// rawExec builds a ring buffer record the way the BPF program would.
func rawExec(t *testing.T, argv []byte, truncated bool) []byte {
	t.Helper()
	var r processExecEvent
	r.Hdr = processEvent{
		Type: uint32(processEventTypeEVENT_EXEC), Pid: 4242, Tgid: 4242, Ppid: 1200,
		Uid: 1000, Gid: 1000, Timestamp: 5_000_000_000, CgroupId: 8123, StartTime: 4_999_000_000,
	}
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

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeExecToJSON(t *testing.T) {
	boot := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	raw := rawExec(t, []byte("ls\x00-la\x00/tmp\x00"), false)

	ev, err := decodeExec(raw, boot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"exec","time":"2026-09-23T00:00:05Z","timestamp_ns":5000000000,` +
		`"pid":4242,"tgid":4242,"ppid":1200,"uid":1000,"gid":1000,"cgroup_id":8123,` +
		`"start_time_ns":4999000000,"comm":"ls","filename":"/usr/bin/ls","filename_truncated":false,` +
		`"argv":["ls","-la","/tmp"],"argv_truncated":false}`
	if string(got) != want {
		t.Errorf("JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestDecodeExecTruncatedArgv(t *testing.T) {
	// A full 4 KiB buffer whose last argument was cut off by the kernel.
	long := "cat\x00" + strings.Repeat("a", 4096)
	raw := rawExec(t, []byte(long), true)

	ev, err := decodeExec(raw, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !ev.ArgvTruncated {
		t.Error("ArgvTruncated = false, want true")
	}
	want := []string{"cat", strings.Repeat("a", 4096-4)}
	if !reflect.DeepEqual(ev.Argv, want) {
		t.Errorf("Argv = %d args (last len %d), want 2 args (last len %d)",
			len(ev.Argv), len(ev.Argv[len(ev.Argv)-1]), len(want[1]))
	}
}

func TestDecodeExecEmptyArgv(t *testing.T) {
	ev, err := decodeExec(rawExec(t, nil, false), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(ev.Argv)
	if string(got) != "[]" {
		t.Errorf("empty argv JSON = %s, want []", got)
	}
}

func TestDecodeExecArgvLenOutOfRange(t *testing.T) {
	raw := rawExec(t, []byte("x\x00"), false)
	// Corrupt argv_len to a value larger than the buffer; decode must clamp, not panic.
	off := 48 + 16 + 512
	binary.LittleEndian.PutUint32(raw[off:], 1<<20)
	if _, err := decodeExec(raw, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeExecErrors(t *testing.T) {
	if _, err := decodeExec([]byte{1, 2, 3}, time.Time{}); err == nil {
		t.Error("short record: want error")
	}
	raw := rawExec(t, nil, false)
	binary.LittleEndian.PutUint32(raw[0:], 99)
	if _, err := decodeExec(raw, time.Time{}); err == nil {
		t.Error("wrong type: want error")
	}
}
