// SPDX-License-Identifier: Apache-2.0

// Command anyone-sensor captures process activity with eBPF and prints it as
// JSON lines on stdout. Diagnostics go to stderr.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/anyone-sensor/internal/loader"
)

func main() {
	statsInterval := flag.Duration("stats-interval", 0, "log drop counters to stderr at this interval (0 disables)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log, *statsInterval); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, statsInterval time.Duration) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	l, err := loader.Load()
	if err != nil {
		return err
	}
	defer l.Close()
	log.Info("attached", "hook", "tracepoint/sched/sched_process_exec")

	if statsInterval > 0 {
		go logStats(ctx, log, l, statsInterval)
	}

	w := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(w)
	for ev := range l.Events(ctx) {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
	}

	s, err := l.Stats()
	if err != nil {
		return err
	}
	log.Info("stopped", "kernel_ringbuf_full", s.KernelRingbufFull, "decode_errors", s.DecodeErrors)
	return l.Err()
}

func logStats(ctx context.Context, log *slog.Logger, l *loader.Loader, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s, err := l.Stats()
			if err != nil {
				log.Warn("read stats", "err", err)
				continue
			}
			log.Info("stats", "kernel_ringbuf_full", s.KernelRingbufFull, "decode_errors", s.DecodeErrors)
		}
	}
}
