// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loader

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

// Options configures Load.
type Options struct {
	// HostMode captures every cgroup. Otherwise only cgroups added with
	// AddCgroup are captured; filtering happens in the kernel.
	HostMode bool
}

// Loader owns the loaded BPF objects, their links and the ring buffer reader.
type Loader struct {
	objs  processObjects
	links []link.Link
	rd    *ringbuf.Reader
	boot  time.Time

	decodeErrors atomic.Uint64
	err          atomic.Pointer[error]
}

// Load removes the memlock limit, loads the BPF objects and attaches the
// process hooks. The caller must call Close.
func Load(opts Options) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	boot, err := bootTime()
	if err != nil {
		return nil, err
	}
	l := &Loader{boot: boot}

	spec, err := loadProcess()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := spec.Variables[processVarModeHost].Set(opts.HostMode); err != nil {
		return nil, fmt.Errorf("set mode_host: %w", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load BPF objects: %+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	attach := []struct {
		name string
		fn   func() (link.Link, error)
	}{
		{"tracepoint/sched/sched_process_exec", func() (link.Link, error) {
			return link.Tracepoint("sched", "sched_process_exec", l.objs.HandleExec, nil)
		}},
		{"tp_btf/sched_process_fork", func() (link.Link, error) {
			return link.AttachTracing(link.TracingOptions{Program: l.objs.HandleFork})
		}},
		{"tracepoint/sched/sched_process_exit", func() (link.Link, error) {
			return link.Tracepoint("sched", "sched_process_exit", l.objs.HandleExit, nil)
		}},
	}
	for _, a := range attach {
		lk, err := a.fn()
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attach %s: %w", a.name, err)
		}
		l.links = append(l.links, lk)
	}

	l.rd, err = ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return l, nil
}

// Hooks lists the attached hooks, for logging.
func Hooks() []string {
	return []string{"tracepoint/sched/sched_process_exec", "tp_btf/sched_process_fork", "tracepoint/sched/sched_process_exit"}
}

// AddCgroup starts capturing processes in the cgroup with this ID.
func (l *Loader) AddCgroup(id uint64) error {
	if err := l.objs.TargetCgroups.Put(id, uint8(1)); err != nil {
		return fmt.Errorf("add cgroup %d to target_cgroups: %w", id, err)
	}
	return nil
}

// RemoveCgroup stops capturing processes in the cgroup with this ID.
func (l *Loader) RemoveCgroup(id uint64) error {
	if err := l.objs.TargetCgroups.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove cgroup %d from target_cgroups: %w", id, err)
	}
	return nil
}

// Events starts reading the ring buffer and returns a channel of decoded
// events. The channel is closed when ctx is cancelled or reading fails; Err
// reports the failure, if any. Sends block rather than drop, so a slow
// consumer back-pressures into the ring buffer, where drops are counted.
func (l *Loader) Events(ctx context.Context) <-chan event.Event {
	out := make(chan event.Event, 1024)

	stop := context.AfterFunc(ctx, func() { l.rd.Close() })
	go func() {
		defer close(out)
		defer stop()
		for {
			rec, err := l.rd.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					err = fmt.Errorf("read ring buffer: %w", err)
					l.err.Store(&err)
				}
				return
			}
			ev, err := decode(rec.RawSample, l.boot)
			if err != nil {
				l.decodeErrors.Add(1)
				continue
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// Err returns the error that stopped Events, or nil.
func (l *Loader) Err() error {
	if p := l.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Stats holds drop and error counters.
type Stats struct {
	KernelRingbufFull uint64 // bpf_ringbuf_reserve failures, summed over CPUs
	DecodeErrors      uint64 // records userspace could not decode
}

// Stats reads the current counters.
func (l *Loader) Stats() (Stats, error) {
	var perCPU []uint64
	if err := l.objs.DropCount.Lookup(uint32(processDropReasonDROP_RINGBUF_FULL), &perCPU); err != nil {
		return Stats{}, fmt.Errorf("read drop_count: %w", err)
	}
	var s Stats
	for _, v := range perCPU {
		s.KernelRingbufFull += v
	}
	s.DecodeErrors = l.decodeErrors.Load()
	return s, nil
}

// Close detaches the programs and releases all BPF resources.
func (l *Loader) Close() error {
	var errs []error
	if l.rd != nil {
		errs = append(errs, l.rd.Close())
	}
	for _, lk := range l.links {
		errs = append(errs, lk.Close())
	}
	errs = append(errs, l.objs.Close())
	return errors.Join(errs...)
}

// bootTime returns the wall-clock time at which CLOCK_BOOTTIME was zero.
func bootTime() (time.Time, error) {
	var rt, bt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &rt); err != nil {
		return time.Time{}, fmt.Errorf("clock_gettime(CLOCK_REALTIME): %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt); err != nil {
		return time.Time{}, fmt.Errorf("clock_gettime(CLOCK_BOOTTIME): %w", err)
	}
	return time.Unix(0, rt.Nano()-bt.Nano()), nil
}
