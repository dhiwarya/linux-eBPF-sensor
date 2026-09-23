// SPDX-License-Identifier: Apache-2.0

package proctable

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

const sec = uint64(time.Second)

func TestGUIDStable(t *testing.T) {
	a := GUID("host", "boot", 42, 10*sec)
	if b := GUID("host", "boot", 42, 10*sec); a != b {
		t.Fatalf("GUID not deterministic: %s vs %s", a, b)
	}
	// Kernel ns and /proc ticks for the same process must agree: 10.0012345 s
	// truncates to the same tick as 10.00 s.
	if b := GUID("host", "boot", 42, 10*sec+1_234_500); a != b {
		t.Errorf("GUID differs within one clock tick: %s vs %s", a, b)
	}
	if len(a) != 36 || a[8] != '-' || a[13] != '-' {
		t.Errorf("GUID %q is not UUID-formatted", a)
	}
}

func TestGUIDUnique(t *testing.T) {
	seen := map[string]string{}
	add := func(desc, g string) {
		if prev, ok := seen[g]; ok {
			t.Fatalf("GUID collision between %s and %s", prev, desc)
		}
		seen[g] = desc
	}
	for pid := uint32(1); pid <= 5000; pid++ {
		add(fmt.Sprintf("pid %d", pid), GUID("host", "boot", pid, 10*sec))
	}
	add("other start tick", GUID("host", "boot", 1, 10*sec+nsPerTick))
	add("other boot", GUID("host", "boot2", 1, 10*sec))
	add("other host", GUID("host2", "boot", 1, 10*sec))
}

func newTable(now *time.Time) *Table {
	return New(Config{HostID: "h", BootID: "b", Now: func() time.Time { return *now }})
}

func fork(child, parent uint32, childStart, parentStart uint64) event.Event {
	return event.Event{
		Type:    event.TypeFork,
		Process: event.Process{PID: child, StartTimeNs: childStart},
		Parent:  event.Parent{PID: parent, StartTimeNs: parentStart},
	}
}

func exec(pid uint32, start uint64, ppid uint32, pstart uint64, image string, argv ...string) event.Event {
	return event.Event{
		Type:    event.TypeExec,
		Process: event.Process{PID: pid, StartTimeNs: start, Image: image, Argv: argv},
		Parent:  event.Parent{PID: ppid, StartTimeNs: pstart},
	}
}

func exit(pid uint32, start uint64, ppid uint32, pstart uint64) event.Event {
	return event.Event{
		Type:    event.TypeExit,
		Process: event.Process{PID: pid, StartTimeNs: start},
		Parent:  event.Parent{PID: ppid, StartTimeNs: pstart},
	}
}

// Lineage from a synthetic stream: sh(100) forks 200, 200 execs curl, curl
// forks 300 which execs sh -c.
func TestLineageFromStream(t *testing.T) {
	now := time.Unix(1000, 0)
	tb := newTable(&now)

	stream := []event.Event{
		exec(100, 1*sec, 1, 0, "/bin/sh", "sh"),
		fork(200, 100, 2*sec, 1*sec),
		exec(200, 2*sec, 100, 1*sec, "/usr/bin/curl", "curl", "-s", "x"),
		fork(300, 200, 3*sec, 2*sec),
		exec(300, 3*sec, 200, 2*sec, "/bin/sh", "sh", "-c", "id"),
	}
	var out []event.Event
	for _, ev := range stream {
		tb.Handle(&ev)
		out = append(out, ev)
	}

	// The fork of 200 inherits sh's image until it execs.
	if got := out[1].Process.Image; got != "/bin/sh" {
		t.Errorf("forked child image = %q, want /bin/sh", got)
	}
	// curl's parent is sh.
	if p := out[2].Parent; !p.Known || p.Image != "/bin/sh" || p.GUID != tb.GUID(100, 1*sec) {
		t.Errorf("curl parent = %+v", p)
	}
	// The last exec's parent is curl, with its argv.
	if p := out[4].Parent; p.Image != "/usr/bin/curl" || !reflect.DeepEqual(p.Argv, []string{"curl", "-s", "x"}) {
		t.Errorf("sh -c parent = %+v", p)
	}

	// Walk the chain by GUID.
	var chain []string
	for g := out[4].Process.GUID; g != ""; {
		e, ok := tb.Lookup(g)
		if !ok {
			break
		}
		chain = append(chain, e.Image)
		g = e.ParentGUID
	}
	if want := []string{"/bin/sh", "/usr/bin/curl", "/bin/sh"}; !reflect.DeepEqual(chain, want) {
		t.Errorf("chain = %v, want %v", chain, want)
	}
}

// A process reparented to init still reports its original parent.
func TestReparentKeepsOriginalParent(t *testing.T) {
	now := time.Unix(1000, 0)
	tb := newTable(&now)
	for _, ev := range []event.Event{
		exec(100, 1*sec, 1, 0, "/bin/bash", "bash"),
		fork(200, 100, 2*sec, 1*sec),
		exit(100, 1*sec, 1, 0),
	} {
		tb.Handle(&ev)
	}
	// 200 is now a child of PID 1 in the kernel's view.
	ev := exec(200, 2*sec, 1, 0, "/bin/sleep", "sleep", "60")
	tb.Handle(&ev)
	if ev.Parent.PID != 100 || ev.Parent.Image != "/bin/bash" {
		t.Errorf("parent = %+v, want original parent bash (100)", ev.Parent)
	}
}

// PID reuse: a new process with the same PID but a later start time is a
// different process and must not inherit the old one's identity or lineage.
func TestPIDReuse(t *testing.T) {
	now := time.Unix(1000, 0)
	tb := newTable(&now)

	old := exec(500, 1*sec, 1, 0, "/usr/bin/old", "old")
	tb.Handle(&old)
	ex := exit(500, 1*sec, 1, 0)
	tb.Handle(&ex)

	reused := exec(500, 9*sec, 1, 0, "/usr/bin/new", "new")
	tb.Handle(&reused)

	if old.Process.GUID == reused.Process.GUID {
		t.Fatal("reused PID got the same GUID")
	}
	a, _ := tb.Lookup(old.Process.GUID)
	b, _ := tb.Lookup(reused.Process.GUID)
	if a.Image != "/usr/bin/old" || b.Image != "/usr/bin/new" {
		t.Errorf("entries mixed up: old=%q new=%q", a.Image, b.Image)
	}
	if !b.ExitedAt.IsZero() {
		t.Error("new process marked exited")
	}

	// A child naming PID 500 with the new start time links to the new process.
	child := exec(600, 10*sec, 500, 9*sec, "/bin/true", "true")
	tb.Handle(&child)
	if child.Parent.Image != "/usr/bin/new" {
		t.Errorf("child parent image = %q, want /usr/bin/new", child.Parent.Image)
	}
}

func TestEvictAfterExit(t *testing.T) {
	now := time.Unix(1000, 0)
	tb := newTable(&now)
	ev := exec(100, 1*sec, 1, 0, "/bin/x")
	tb.Handle(&ev)
	ex := exit(100, 1*sec, 1, 0)
	tb.Handle(&ex)

	now = now.Add(29 * time.Second)
	if n := tb.Sweep(); n != 0 {
		t.Fatalf("evicted %d entries before ExitTTL", n)
	}
	now = now.Add(2 * time.Second)
	if n := tb.Sweep(); n != 1 {
		t.Fatalf("evicted %d entries after ExitTTL, want 1", n)
	}
	if _, ok := tb.Lookup(ev.Process.GUID); ok {
		t.Error("entry still present after eviction")
	}
	if s := tb.Stats(); s.EvictedExit != 1 || s.Entries != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestLRUCap(t *testing.T) {
	now := time.Unix(1000, 0)
	tb := New(Config{HostID: "h", BootID: "b", MaxEntries: 3, Now: func() time.Time { return now }})
	for pid := uint32(1); pid <= 3; pid++ {
		ev := exec(pid, uint64(pid)*sec, 0, 0, "/bin/x")
		tb.Handle(&ev)
	}
	// Touch pid 1 so pid 2 becomes least recently used.
	touch := exec(1, 1*sec, 0, 0, "/bin/x")
	tb.Handle(&touch)
	ev := exec(4, 4*sec, 0, 0, "/bin/x")
	tb.Handle(&ev)

	if _, ok := tb.Lookup(tb.GUID(2, 2*sec)); ok {
		t.Error("least recently used entry (pid 2) was not evicted")
	}
	for _, pid := range []uint32{1, 3, 4} {
		if _, ok := tb.Lookup(tb.GUID(pid, uint64(pid)*sec)); !ok {
			t.Errorf("pid %d evicted", pid)
		}
	}
	if s := tb.Stats(); s.Entries != 3 || s.EvictedLRU != 1 {
		t.Errorf("stats = %+v", s)
	}
}

type fakeProc map[uint32]ProcInfo

func (f fakeProc) Read(pid uint32) (ProcInfo, error) {
	if p, ok := f[pid]; ok {
		return p, nil
	}
	return ProcInfo{}, errors.New("no such process")
}

// A parent outside the capture scope (containerd-shim for docker exec) is
// resolved from /proc and marked external; a PID whose start time does not
// match is not trusted.
func TestExternalParentFromProc(t *testing.T) {
	now := time.Unix(1000, 0)
	target := uint64(77)
	tb := New(Config{
		HostID: "h", BootID: "b", Now: func() time.Time { return now },
		InScope: func(id uint64) bool { return id == target },
		Proc: fakeProc{
			900: {PID: 900, PPID: 1, StartTimeNs: 5 * sec, Image: "/usr/bin/containerd-shim-runc-v2", CgroupID: 1},
		},
	})

	ev := exec(1000, 6*sec, 900, 5*sec, "/bin/sh", "sh", "-c", "sleep 1")
	ev.Process.CgroupID = target
	tb.Handle(&ev)
	if p := ev.Parent; !p.Known || !p.External || p.Image != "/usr/bin/containerd-shim-runc-v2" {
		t.Errorf("parent = %+v, want known external containerd-shim", p)
	}

	// Same PID but a different start time: a reused PID, not our parent.
	ev2 := exec(1001, 7*sec, 900, 4*sec, "/bin/sh")
	tb.Handle(&ev2)
	if ev2.Parent.Known {
		t.Errorf("parent with mismatched start time was trusted: %+v", ev2.Parent)
	}
	if s := tb.Stats(); s.ProcLookups != 1 || s.ProcMisses != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestSeed(t *testing.T) {
	now := time.Unix(1000, 0)
	target := uint64(77)
	tb := New(Config{HostID: "h", BootID: "b", Now: func() time.Time { return now },
		InScope: func(id uint64) bool { return id == target }})

	n := tb.Seed([]ProcInfo{
		{PID: 1, PPID: 0, StartTimeNs: 1 * sec, Image: "/sbin/init", CgroupID: 1},
		{PID: 50, PPID: 1, StartTimeNs: 2 * sec, Image: "/bin/sh", Argv: []string{"sh"}, CgroupID: target},
		{PID: 51, PPID: 50, StartTimeNs: 3 * sec, Image: "/bin/sleep", Argv: []string{"sleep", "1000"}, CgroupID: target},
	})
	if n != 2 {
		t.Fatalf("seeded %d, want 2 (host init is out of scope)", n)
	}
	// A new exec by a seeded process's child links to the seeded parent.
	ev := exec(60, 4*sec, 50, 2*sec, "/bin/ls", "ls")
	tb.Handle(&ev)
	if !ev.Parent.Known || ev.Parent.Image != "/bin/sh" {
		t.Errorf("parent = %+v, want seeded /bin/sh", ev.Parent)
	}
	e, _ := tb.Lookup(tb.GUID(51, 3*sec))
	if e.ParentGUID != tb.GUID(50, 2*sec) {
		t.Errorf("seeded parent GUID = %s", e.ParentGUID)
	}
}

func TestParseStat(t *testing.T) {
	// comm with spaces and parentheses.
	line := "1234 (my (weird) cmd) S 99 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 424242 1000 10 0\n"
	ppid, st, err := parseStat([]byte(line))
	if err != nil || ppid != 99 || st != 424242 {
		t.Errorf("parseStat = %d, %d, %v; want 99, 424242, nil", ppid, st, err)
	}
	if _, _, err := parseStat([]byte("garbage")); err == nil {
		t.Error("want error for malformed stat")
	}
}

func TestParseCgroupV2Path(t *testing.T) {
	in := "12:cpu:/ignored\n0::/system.slice/docker-abc.scope\n"
	if got := parseCgroupV2Path([]byte(in)); got != "/system.slice/docker-abc.scope" {
		t.Errorf("got %q", got)
	}
}

func TestProcFSRead(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc", "42")
	cg := filepath.Join(root, "cgroup", "system.slice", "docker-abc.scope")
	for _, d := range []string{proc, cg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(proc, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "42 (sh) S 7 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1500 0 0 0\n")
	write("cmdline", "sh\x00-c\x00sleep 9\x00")
	write("cgroup", "0::/system.slice/docker-abc.scope\n")
	if err := os.Symlink("/bin/busybox", filepath.Join(proc, "exe")); err != nil {
		t.Fatal(err)
	}

	p := &ProcFS{ProcRoot: filepath.Join(root, "proc"), CgroupRoot: filepath.Join(root, "cgroup")}
	info, err := p.Read(42)
	if err != nil {
		t.Fatal(err)
	}
	ino, _ := InodeOf(cg)
	want := ProcInfo{PID: 42, PPID: 7, StartTimeNs: 1500 * nsPerTick, Image: "/bin/busybox",
		Argv: []string{"sh", "-c", "sleep 9"}, CgroupID: ino}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("Read = %+v\nwant   %+v", info, want)
	}
}
