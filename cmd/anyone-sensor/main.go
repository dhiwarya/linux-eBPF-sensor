// SPDX-License-Identifier: Apache-2.0

// Command anyone-sensor captures process activity with eBPF and prints it as
// JSON lines on stdout. Diagnostics go to stderr.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/container"
	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
	"github.com/dhiwarya/linux-eBPF-sensor/internal/loader"
	"github.com/dhiwarya/linux-eBPF-sensor/internal/proctable"
)

type options struct {
	mode          string
	target        container.Target
	dockerSocket  string
	statsInterval time.Duration
	maxProcs      int
}

func main() {
	var o options
	flag.StringVar(&o.mode, "mode", "container", "capture scope: container (one target container) or host (everything)")
	flag.StringVar(&o.target.Name, "container", "", "target container name")
	flag.StringVar(&o.target.ID, "container-id", "", "target container ID (full or unique prefix)")
	flag.StringVar(&o.target.Label, "container-label", "", "target container label, key=value")
	flag.StringVar(&o.dockerSocket, "docker-socket", "/var/run/docker.sock", "Docker Engine API socket")
	flag.DurationVar(&o.statsInterval, "stats-interval", 0, "log counters to stderr at this interval (0 disables)")
	flag.IntVar(&o.maxProcs, "max-procs", 100_000, "process table hard cap")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log, o); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, o options) error {
	hostMode := false
	switch o.mode {
	case "host":
		hostMode = true
	case "container":
		if err := o.target.Validate(); err != nil {
			return fmt.Errorf("container mode needs a target (-container, -container-id or -container-label): %w", err)
		}
	default:
		return fmt.Errorf("-mode must be container or host, got %q", o.mode)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	hostID, bootID, err := proctable.HostIdentity()
	if err != nil {
		return err
	}

	// 1. Load with an empty target map: nothing is captured yet.
	l, err := loader.Load(loader.Options{HostMode: hostMode})
	if err != nil {
		return err
	}
	defer l.Close()
	log.Info("attached", "hooks", loader.Hooks(), "mode", o.mode)

	// 2. Resolve the target and capture its cgroup; events now buffer.
	var watcher *container.Watcher
	var inScope func(uint64) bool
	if !hostMode {
		watcher = container.NewWatcher(container.WatcherConfig{
			Runtime: container.NewDocker(o.dockerSocket),
			Target:  o.target,
			Cgroups: l,
			Log:     log,
		})
		if err := watcher.Start(ctx); err != nil {
			return err
		}
		inScope = watcher.InScope
	}

	// 3. Seed lineage from /proc, then 4. consume events.
	procfs := proctable.NewProcFS()
	table := proctable.New(proctable.Config{
		HostID: hostID, BootID: bootID, MaxEntries: o.maxProcs, InScope: inScope, Proc: procfs,
	})
	procs, err := procfs.Scan()
	if err != nil {
		return fmt.Errorf("scan /proc: %w", err)
	}
	log.Info("seeded process table from /proc", "processes", table.Seed(procs))

	go every(ctx, 5*time.Second, func() { table.Sweep() })
	if o.statsInterval > 0 {
		go every(ctx, o.statsInterval, func() { logStats(log, l, table) })
	}

	w := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(w)
	for ev := range l.Events(ctx) {
		table.Handle(&ev)
		if watcher != nil {
			if c, ok := watcher.Lookup(ev.Process.CgroupID); ok {
				ev.Container = &event.Container{ID: c.ID, Name: c.Name, Image: c.Image}
			}
		}
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
	}

	logStats(log, l, table)
	if err := l.Err(); err != nil {
		return err
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	return nil
}

func logStats(log *slog.Logger, l *loader.Loader, t *proctable.Table) {
	s, err := l.Stats()
	if err != nil {
		log.Warn("read stats", "err", err)
		return
	}
	p := t.Stats()
	log.Info("stats",
		"kernel_ringbuf_full", s.KernelRingbufFull, "decode_errors", s.DecodeErrors,
		"proctable_entries", p.Entries, "evicted_exit", p.EvictedExit, "evicted_lru", p.EvictedLRU,
		"proc_lookups", p.ProcLookups, "proc_misses", p.ProcMisses, "unknown_exits", p.UnknownExits)
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}
