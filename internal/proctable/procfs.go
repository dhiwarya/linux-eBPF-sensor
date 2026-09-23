// SPDX-License-Identifier: Apache-2.0

package proctable

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/dhiwarya/linux-eBPF-sensor/internal/event"
)

// maxCmdline matches the kernel-side argv bound.
const maxCmdline = 4096

// ProcInfo is what /proc tells us about one process.
type ProcInfo struct {
	PID         uint32
	PPID        uint32
	StartTimeNs uint64 // tick precision
	Image       string
	Argv        []string
	CgroupID    uint64
}

// ProcFS reads process information from a procfs and cgroup2 mount.
type ProcFS struct {
	ProcRoot   string // usually /proc
	CgroupRoot string // usually /sys/fs/cgroup
}

// NewProcFS returns a ProcFS for the host's /proc and /sys/fs/cgroup.
func NewProcFS() *ProcFS {
	return &ProcFS{ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup"}
}

// Read returns information about one process.
func (p *ProcFS) Read(pid uint32) (ProcInfo, error) {
	dir := filepath.Join(p.ProcRoot, strconv.FormatUint(uint64(pid), 10))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ProcInfo{}, err
	}
	ppid, ticks, err := parseStat(stat)
	if err != nil {
		return ProcInfo{}, fmt.Errorf("pid %d: %w", pid, err)
	}
	info := ProcInfo{PID: pid, PPID: ppid, StartTimeNs: ticks * nsPerTick}

	// Kernel threads have no exe and an empty cmdline; leave those empty.
	info.Image, _ = os.Readlink(filepath.Join(dir, "exe"))
	if f, err := os.Open(filepath.Join(dir, "cmdline")); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, maxCmdline))
		f.Close()
		info.Argv = event.SplitArgv(b)
	}
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		info.CgroupID, _ = p.CgroupID(parseCgroupV2Path(cg))
	}
	return info, nil
}

// Scan reads every process in /proc. Processes that exit mid-scan are skipped.
func (p *ProcFS) Scan() ([]ProcInfo, error) {
	ents, err := os.ReadDir(p.ProcRoot)
	if err != nil {
		return nil, err
	}
	var out []ProcInfo
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		info, err := p.Read(uint32(pid))
		if err != nil {
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// CgroupID returns the cgroup v2 ID of a cgroup path such as
// /system.slice/docker-<id>.scope: the inode number of its directory. It is
// not cached: a container restart recreates the same path with a new inode.
func (p *ProcFS) CgroupID(path string) (uint64, error) {
	if path == "" {
		return 0, errors.New("empty cgroup path")
	}
	return InodeOf(filepath.Join(p.CgroupRoot, path))
}

// InodeOf returns the inode number of path. For a cgroup v2 directory this is
// the cgroup ID that bpf_get_current_cgroup_id() returns.
func InodeOf(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no inode", path)
	}
	return st.Ino, nil
}

// parseStat extracts ppid and starttime (clock ticks) from /proc/<pid>/stat.
// comm (field 2) may contain spaces and parentheses, so fields are counted
// from the last ')'.
func parseStat(b []byte) (ppid uint32, startTicks uint64, err error) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, 0, errors.New("malformed stat: no ')'")
	}
	f := strings.Fields(string(b[i+1:]))
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 20 {
		return 0, 0, fmt.Errorf("malformed stat: %d fields after comm", len(f))
	}
	pp, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse ppid: %w", err)
	}
	st, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse starttime: %w", err)
	}
	return uint32(pp), st, nil
}

// parseCgroupV2Path returns the unified hierarchy path from /proc/<pid>/cgroup
// (the "0::<path>" line).
func parseCgroupV2Path(b []byte) string {
	for line := range strings.SplitSeq(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
	}
	return ""
}
