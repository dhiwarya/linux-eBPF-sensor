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

	"github.com/example/anyone-sensor/internal/event"
)

// Loader owns the loaded BPF objects, their links and the ring buffer reader.
type Loader struct {
	objs processObjects
	exec link.Link
	rd   *ringbuf.Reader
	boot time.Time

	decodeErrors atomic.Uint64
	err          atomic.Pointer[error]
}

// Load removes the memlock limit, loads the BPF objects and attaches the exec
// tracepoint. The caller must call Close.
func Load() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	boot, err := bootTime()
	if err != nil {
		return nil, err
	}
	l := &Loader{boot: boot}

	if err := loadProcessObjects(&l.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load BPF objects: %+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	l.exec, err = link.Tracepoint("sched", "sched_process_exec", l.objs.HandleExec, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach tracepoint sched/sched_process_exec: %w", err)
	}

	l.rd, err = ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return l, nil
}

// Events starts reading the ring buffer and returns a channel of decoded exec
// events. The channel is closed when ctx is cancelled or reading fails; Err
// reports the failure, if any. Sends block rather than drop, so a slow
// consumer back-pressures into the ring buffer, where drops are counted.
func (l *Loader) Events(ctx context.Context) <-chan event.Exec {
	out := make(chan event.Exec, 1024)

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
			ev, err := decodeExec(rec.RawSample, l.boot)
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
	if l.exec != nil {
		errs = append(errs, l.exec.Close())
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
