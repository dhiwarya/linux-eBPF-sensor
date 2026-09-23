// SPDX-License-Identifier: Apache-2.0

// Package proctable tracks processes by GUID so events can carry stable
// process identifiers and their parent's image and argv.
package proctable

import (
	"container/list"
	"slices"
	"sync"
	"time"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

// Entry is one process. Entries are keyed strictly by GUID.
type Entry struct {
	GUID        string
	ParentGUID  string // parent at fork time (original lineage), "" if unknown
	PID         uint32
	PPID        uint32
	StartTimeNs uint64
	Image       string
	Argv        []string
	CgroupID    uint64
	// External marks a process outside the capture scope that was read from
	// /proc because a captured process named it as parent.
	External bool
	ExitedAt time.Time // zero while running

	elem *list.Element
}

// Config configures a Table.
type Config struct {
	HostID, BootID string
	MaxEntries     int           // hard cap; least recently used entries are evicted beyond it
	ExitTTL        time.Duration // how long exited entries are kept
	// InScope reports whether a cgroup is captured. Nil means everything is.
	InScope func(cgroupID uint64) bool
	// Proc resolves unknown parents. Nil disables /proc lookups.
	Proc interface {
		Read(pid uint32) (ProcInfo, error)
	}
	Now func() time.Time // for tests; defaults to time.Now
}

// Stats are table counters.
type Stats struct {
	Entries      int
	EvictedExit  uint64 // removed ExitTTL after exit
	EvictedLRU   uint64 // removed because MaxEntries was reached
	ProcLookups  uint64 // unknown parents resolved from /proc
	ProcMisses   uint64 // unknown parents not found (or PID reused) in /proc
	UnknownExits uint64 // exits of processes the table never saw
}

// Table is safe for concurrent use.
type Table struct {
	cfg Config

	mu      sync.Mutex
	entries map[string]*Entry
	lru     *list.List // front = most recently used; values are *Entry
	stats   Stats
}

// New returns an empty table.
func New(cfg Config) *Table {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 100_000
	}
	if cfg.ExitTTL <= 0 {
		cfg.ExitTTL = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Table{cfg: cfg, entries: map[string]*Entry{}, lru: list.New()}
}

// GUID returns the GUID for a process on this host and boot.
func (t *Table) GUID(tgid uint32, startNs uint64) string {
	return GUID(t.cfg.HostID, t.cfg.BootID, tgid, startNs)
}

// Seed adds processes read from /proc at startup. Only in-scope processes are
// added; their parents are linked by GUID using the parents' own start times.
func (t *Table) Seed(procs []ProcInfo) int {
	start := make(map[uint32]uint64, len(procs))
	for _, p := range procs {
		start[p.PID] = p.StartTimeNs
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, p := range procs {
		if !t.inScope(p.CgroupID) {
			continue
		}
		e := &Entry{
			GUID:        t.GUID(p.PID, p.StartTimeNs),
			PID:         p.PID,
			PPID:        p.PPID,
			StartTimeNs: p.StartTimeNs,
			Image:       p.Image,
			Argv:        p.Argv,
			CgroupID:    p.CgroupID,
		}
		if ps, ok := start[p.PPID]; ok && p.PPID != 0 {
			e.ParentGUID = t.GUID(p.PPID, ps)
		}
		if _, exists := t.entries[e.GUID]; !exists {
			t.insert(e)
			n++
		}
	}
	return n
}

// Handle updates the table from a kernel event and enriches the event with
// GUIDs and parent details.
func (t *Table) Handle(ev *event.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	guid := t.GUID(ev.Process.PID, ev.Process.StartTimeNs)
	hdrParent := t.GUID(ev.Parent.PID, ev.Parent.StartTimeNs)
	ev.Process.GUID = guid

	e := t.get(guid)
	switch ev.Type {
	case event.TypeFork:
		if e == nil {
			e = t.newEntry(ev, guid, hdrParent)
			// A forked child runs its parent's image until it execs.
			if p := t.parent(hdrParent, ev.Parent.PID, ev.Parent.StartTimeNs); p != nil {
				e.Image, e.Argv = p.Image, p.Argv
			}
			t.insert(e)
		}
	case event.TypeExec:
		if e == nil {
			e = t.newEntry(ev, guid, hdrParent)
			t.insert(e)
		}
		e.Image, e.Argv = ev.Process.Image, ev.Process.Argv
		e.External = false
	case event.TypeExit:
		if e == nil {
			t.stats.UnknownExits++
		} else if e.ExitedAt.IsZero() {
			e.ExitedAt = t.cfg.Now()
		}
	}

	if e != nil && ev.Type != event.TypeExec {
		ev.Process.Image, ev.Process.Argv = e.Image, e.Argv
	}

	// Prefer the original (fork-time) parent; fall back to the kernel's
	// current real_parent, which changes when a process is reparented.
	parentGUID, ppid, pstart := hdrParent, ev.Parent.PID, ev.Parent.StartTimeNs
	if e != nil && e.ParentGUID != "" && e.ParentGUID != hdrParent {
		if p := t.get(e.ParentGUID); p != nil {
			parentGUID, ppid, pstart = p.GUID, p.PID, p.StartTimeNs
		}
	}
	ev.Parent.GUID, ev.Parent.PID, ev.Parent.StartTimeNs = parentGUID, ppid, pstart
	if p := t.parent(parentGUID, ppid, pstart); p != nil {
		ev.Parent.Known = true
		ev.Parent.External = p.External
		ev.Parent.Image, ev.Parent.Argv = p.Image, p.Argv
	}
}

// Lookup returns a copy of the entry for guid.
func (t *Table) Lookup(guid string) (Entry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[guid]
	if !ok {
		return Entry{}, false
	}
	c := *e
	c.Argv = slices.Clone(e.Argv)
	c.elem = nil
	return c, true
}

// Sweep removes entries that exited more than ExitTTL ago.
func (t *Table) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.cfg.Now().Add(-t.cfg.ExitTTL)
	n := 0
	for guid, e := range t.entries {
		if !e.ExitedAt.IsZero() && e.ExitedAt.Before(cutoff) {
			t.remove(guid, e)
			t.stats.EvictedExit++
			n++
		}
	}
	return n
}

// Stats returns the current counters.
func (t *Table) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stats
	s.Entries = len(t.entries)
	return s
}

func (t *Table) inScope(cgroupID uint64) bool {
	return t.cfg.InScope == nil || t.cfg.InScope(cgroupID)
}

func (t *Table) newEntry(ev *event.Event, guid, parentGUID string) *Entry {
	return &Entry{
		GUID:        guid,
		ParentGUID:  parentGUID,
		PID:         ev.Process.PID,
		PPID:        ev.Parent.PID,
		StartTimeNs: ev.Process.StartTimeNs,
		CgroupID:    ev.Process.CgroupID,
	}
}

// parent returns the entry for a parent, resolving it from /proc if unknown.
// The /proc result is only trusted if its start time matches, so a reused
// PID is never mistaken for the parent.
func (t *Table) parent(guid string, pid uint32, startNs uint64) *Entry {
	if e := t.get(guid); e != nil {
		return e
	}
	if t.cfg.Proc == nil || pid == 0 {
		return nil
	}
	info, err := t.cfg.Proc.Read(pid)
	if err != nil || StartTicks(info.StartTimeNs) != StartTicks(startNs) {
		t.stats.ProcMisses++
		return nil
	}
	t.stats.ProcLookups++
	e := &Entry{
		GUID:        guid,
		PID:         info.PID,
		PPID:        info.PPID,
		StartTimeNs: info.StartTimeNs,
		Image:       info.Image,
		Argv:        info.Argv,
		CgroupID:    info.CgroupID,
		External:    !t.inScope(info.CgroupID),
	}
	t.insert(e)
	return e
}

func (t *Table) get(guid string) *Entry {
	e, ok := t.entries[guid]
	if !ok {
		return nil
	}
	t.lru.MoveToFront(e.elem)
	return e
}

func (t *Table) insert(e *Entry) {
	e.elem = t.lru.PushFront(e)
	t.entries[e.GUID] = e
	for len(t.entries) > t.cfg.MaxEntries {
		old := t.lru.Back().Value.(*Entry)
		t.remove(old.GUID, old)
		t.stats.EvictedLRU++
	}
}

func (t *Table) remove(guid string, e *Entry) {
	t.lru.Remove(e.elem)
	delete(t.entries, guid)
}
