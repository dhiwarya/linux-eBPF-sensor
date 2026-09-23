// SPDX-License-Identifier: Apache-2.0

//go:build linux

package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// CgroupMap is the kernel-side set of captured cgroups (loader.Loader).
type CgroupMap interface {
	AddCgroup(id uint64) error
	RemoveCgroup(id uint64) error
}

// WatcherConfig configures a Watcher.
type WatcherConfig struct {
	Runtime    Runtime
	Target     Target
	Cgroups    CgroupMap
	CgroupRoot string        // usually /sys/fs/cgroup
	Grace      time.Duration // how long an old cgroup ID stays captured after the container stops
	Log        *slog.Logger
}

// Watcher keeps the target container's cgroup IDs in the kernel map and
// provides container metadata by cgroup ID.
//
// A container restart creates a new cgroup directory, hence a new cgroup ID.
// Docker's "start" event arrives only after the entrypoint has exec'd, so the
// watcher also watches the cgroup parent directory with inotify: runc creates
// the directory before the container's process runs, so the new ID is in the
// kernel map before the entrypoint's first exec.
type Watcher struct {
	cfg WatcherConfig

	mu       sync.Mutex
	wanted   *Container           // the current target container
	byCgroup map[uint64]Container // captured cgroups, including those in grace
	timers   map[uint64]*time.Timer
}

// NewWatcher returns a Watcher. Call Start to resolve the target.
func NewWatcher(cfg WatcherConfig) *Watcher {
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = "/sys/fs/cgroup"
	}
	if cfg.Grace <= 0 {
		cfg.Grace = 5 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Watcher{cfg: cfg, byCgroup: map[uint64]Container{}, timers: map[uint64]*time.Timer{}}
}

// Start resolves the target, adds its cgroup if it is running, and watches
// for changes until ctx is done. A target that does not exist yet is not an
// error: it is picked up when it is created.
func (w *Watcher) Start(ctx context.Context) error {
	if err := w.cfg.Target.Validate(); err != nil {
		return err
	}
	if err := w.resync(ctx, "initial"); err != nil {
		return err
	}

	// The parent directory is the same for every container of this runtime.
	probe, err := w.cfg.Runtime.CgroupPath(ctx, "0")
	if err != nil {
		return err
	}
	parent := filepath.Join(w.cfg.CgroupRoot, filepath.Dir(probe))
	if err := w.watchCgroupDir(ctx, parent); err != nil {
		return fmt.Errorf("watch %s: %w", parent, err)
	}
	go w.runtimeEvents(ctx)
	return nil
}

// Lookup returns the container that owns a cgroup ID.
func (w *Watcher) Lookup(cgroupID uint64) (Container, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	c, ok := w.byCgroup[cgroupID]
	return c, ok
}

// InScope reports whether a cgroup ID is currently captured.
func (w *Watcher) InScope(cgroupID uint64) bool {
	_, ok := w.Lookup(cgroupID)
	return ok
}

// CgroupIDs returns the captured cgroup IDs.
func (w *Watcher) CgroupIDs() []uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]uint64, 0, len(w.byCgroup))
	for id := range w.byCgroup {
		ids = append(ids, id)
	}
	return ids
}

// resync lists containers and reconciles the target with them.
func (w *Watcher) resync(ctx context.Context, why string) error {
	all, err := w.cfg.Runtime.List(ctx)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	var matches []Container
	for _, c := range all {
		if w.cfg.Target.Matches(c) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		w.cfg.Log.Warn("target container not found; waiting for it to be created", "target", w.cfg.Target.String())
		return nil
	case 1:
	default:
		// Prefer the single running one, e.g. an old stopped container with
		// the same label next to its replacement.
		var running []Container
		for _, c := range matches {
			if c.Running {
				running = append(running, c)
			}
		}
		if len(running) != 1 {
			return fmt.Errorf("target %s matches %d containers; it must select exactly one", w.cfg.Target, len(matches))
		}
		matches = running
	}
	c := matches[0]
	w.setWanted(c)
	if c.Running {
		return w.addRunning(ctx, c, why)
	}
	w.cfg.Log.Info("target container is not running; waiting for it to start", "id", short(c.ID), "name", c.Name)
	return nil
}

func (w *Watcher) setWanted(c Container) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wanted == nil || w.wanted.ID != c.ID {
		w.cfg.Log.Info("target container", "id", short(c.ID), "name", c.Name, "image", c.Image)
	}
	w.wanted = &c
}

func (w *Watcher) wantedContainer() (Container, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wanted == nil {
		return Container{}, false
	}
	return *w.wanted, true
}

// addRunning resolves a running container's cgroup and captures it.
func (w *Watcher) addRunning(ctx context.Context, c Container, why string) error {
	path, err := w.cgroupPath(ctx, c)
	if err != nil {
		return err
	}
	id, err := inode(filepath.Join(w.cfg.CgroupRoot, path))
	if err != nil {
		return fmt.Errorf("container %s: cgroup %s: %w", short(c.ID), path, err)
	}
	return w.add(id, c, why)
}

// cgroupPath prefers the init process's actual cgroup, which also covers
// runtimes configured with a non-default cgroup parent.
func (w *Watcher) cgroupPath(ctx context.Context, c Container) (string, error) {
	if c.Pid > 0 {
		if b, err := os.ReadFile("/proc/" + strconv.Itoa(c.Pid) + "/cgroup"); err == nil {
			for line := range strings.SplitSeq(string(b), "\n") {
				if p, ok := strings.CutPrefix(line, "0::"); ok && p != "" && p != "/" {
					return p, nil
				}
			}
		}
	}
	return w.cfg.Runtime.CgroupPath(ctx, c.ID)
}

func (w *Watcher) add(id uint64, c Container, why string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.timers[id]; ok {
		t.Stop()
		delete(w.timers, id)
	}
	if _, ok := w.byCgroup[id]; ok {
		w.byCgroup[id] = c
		return nil
	}
	if err := w.cfg.Cgroups.AddCgroup(id); err != nil {
		return err
	}
	w.byCgroup[id] = c
	w.cfg.Log.Info("capturing cgroup", "cgroup_id", id, "container", short(c.ID), "name", c.Name, "via", why)
	return nil
}

// release keeps capturing a cgroup for the grace period, then removes it.
func (w *Watcher) release(id uint64, why string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.byCgroup[id]; !ok {
		return
	}
	if _, pending := w.timers[id]; pending {
		return
	}
	w.cfg.Log.Info("cgroup ending; keeping it for the grace period", "cgroup_id", id, "grace", w.cfg.Grace, "via", why)
	w.timers[id] = time.AfterFunc(w.cfg.Grace, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.timers, id)
		delete(w.byCgroup, id)
		if err := w.cfg.Cgroups.RemoveCgroup(id); err != nil {
			w.cfg.Log.Warn("remove cgroup", "cgroup_id", id, "err", err)
			return
		}
		w.cfg.Log.Info("stopped capturing cgroup", "cgroup_id", id)
	})
}

// releaseContainer releases the container's cgroups, except the one that is
// currently live on disk. Runtime events and inotify arrive on different
// goroutines, so on a restart the old container's "die" can be handled after
// the new cgroup was already added; checking the live inode keeps the new one.
func (w *Watcher) releaseContainer(ctx context.Context, id, why string) {
	live := uint64(0)
	if path, err := w.cfg.Runtime.CgroupPath(ctx, id); err == nil {
		live, _ = inode(filepath.Join(w.cfg.CgroupRoot, path))
	}
	w.mu.Lock()
	var ids []uint64
	for cg, c := range w.byCgroup {
		if c.ID == id && cg != live {
			ids = append(ids, cg)
		}
	}
	w.mu.Unlock()
	for _, cg := range ids {
		w.release(cg, why)
	}
}

// runtimeEvents follows the runtime's event stream, reconnecting with
// backoff. After every reconnect it resyncs, since events may have been missed.
func (w *Watcher) runtimeEvents(ctx context.Context) {
	backoff := time.Second
	for first := true; ctx.Err() == nil; first = false {
		if !first {
			if err := w.resync(ctx, "resync"); err != nil {
				w.cfg.Log.Warn("resync", "err", err)
			}
		}
		evs, errc := w.cfg.Runtime.Events(ctx)
		for ev := range evs {
			backoff = time.Second
			w.handle(ctx, ev)
		}
		select {
		case err := <-errc:
			w.cfg.Log.Warn("container runtime event stream ended; reconnecting", "err", err, "in", backoff)
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (w *Watcher) handle(ctx context.Context, ev Event) {
	switch ev.Kind {
	case EventCreate, EventStart, EventRename:
		c, err := w.cfg.Runtime.Inspect(ctx, ev.ID)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				w.cfg.Log.Warn("inspect container", "id", short(ev.ID), "err", err)
			}
			return
		}
		cur, ok := w.wantedContainer()
		switch {
		case w.cfg.Target.Matches(c):
			w.setWanted(c)
			if ev.Kind == EventStart && c.Running {
				if err := w.addRunning(ctx, c, "runtime start event"); err != nil {
					w.cfg.Log.Warn("add started container", "id", short(c.ID), "err", err)
				}
			}
		case ok && cur.ID == c.ID:
			// Renamed away from the target name.
			w.cfg.Log.Info("container no longer matches target", "id", short(c.ID), "name", c.Name)
			w.releaseContainer(ctx, c.ID, "renamed")
			w.mu.Lock()
			w.wanted = nil
			w.mu.Unlock()
		}
	case EventDie:
		w.releaseContainer(ctx, ev.ID, "runtime die event")
	case EventDestroy:
		w.releaseContainer(ctx, ev.ID, "runtime destroy event")
		w.mu.Lock()
		if w.wanted != nil && w.wanted.ID == ev.ID {
			w.wanted = nil
		}
		w.mu.Unlock()
	}
}

// watchCgroupDir captures the target's cgroup as soon as its directory is
// created, and starts the grace period when it is removed.
func (w *Watcher) watchCgroupDir(ctx context.Context, dir string) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_CREATE|unix.IN_DELETE|unix.IN_ONLYDIR); err != nil {
		unix.Close(fd)
		return fmt.Errorf("inotify_add_watch: %w", err)
	}
	// A non-blocking fd makes os.File use the runtime poller, so Close
	// unblocks Read.
	f := os.NewFile(uintptr(fd), "inotify:"+dir)
	context.AfterFunc(ctx, func() { f.Close() })

	go func() {
		buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
		for {
			n, err := f.Read(buf)
			if err != nil {
				if ctx.Err() == nil {
					w.cfg.Log.Warn("inotify read; relying on runtime events only", "dir", dir, "err", err)
				}
				return
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(raw.Len)]
				name := strings.TrimRight(string(nameBytes), "\x00")
				off += unix.SizeofInotifyEvent + int(raw.Len)
				w.cgroupDirEvent(ctx, dir, name, raw.Mask)
			}
		}
	}()
	return nil
}

func (w *Watcher) cgroupDirEvent(ctx context.Context, dir, name string, mask uint32) {
	c, ok := w.wantedContainer()
	if !ok {
		return
	}
	want, err := w.cfg.Runtime.CgroupPath(ctx, c.ID)
	if err != nil || filepath.Base(want) != name {
		return
	}
	path := filepath.Join(dir, name)
	switch {
	case mask&unix.IN_CREATE != 0:
		id, err := inode(path)
		if err != nil {
			w.cfg.Log.Warn("stat new cgroup", "path", path, "err", err)
			return
		}
		if err := w.add(id, c, "inotify cgroup create"); err != nil {
			w.cfg.Log.Warn("add cgroup", "cgroup_id", id, "err", err)
		}
	case mask&unix.IN_DELETE != 0:
		w.releaseContainer(ctx, c.ID, "inotify cgroup delete")
	}
}

func inode(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
