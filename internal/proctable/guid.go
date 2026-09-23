// SPDX-License-Identifier: Apache-2.0

package proctable

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// nsPerTick converts CLOCK_BOOTTIME nanoseconds to the clock ticks that
// /proc/<pid>/stat reports. USER_HZ is 100 on every Linux architecture the
// sensor supports, and the kernel computes starttime as start_boottime /
// (NSEC_PER_SEC / USER_HZ), so truncating here gives the identical value.
const nsPerTick = 1_000_000_000 / 100

// StartTicks returns the /proc-compatible start time for a kernel start time.
func StartTicks(startNs uint64) uint64 { return startNs / nsPerTick }

// GUID returns the stable identifier of a process: a hash of the host, the
// boot, the process ID and its start time in clock ticks. The same process
// gets the same GUID from kernel events and from /proc, across sensor
// restarts; a reused PID gets a different GUID because its start time differs.
func GUID(hostID, bootID string, tgid uint32, startNs uint64) string {
	h := sha256.New()
	h.Write([]byte(hostID))
	h.Write([]byte{0})
	h.Write([]byte(bootID))
	h.Write([]byte{0})
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:], tgid)
	binary.LittleEndian.PutUint64(b[4:], StartTicks(startNs))
	h.Write(b[:])
	s := hex.EncodeToString(h.Sum(nil)[:16])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// HostIdentity reads the machine ID and boot ID used in GUIDs.
func HostIdentity() (hostID, bootID string, err error) {
	host, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", "", fmt.Errorf("read host ID: %w", err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", "", fmt.Errorf("read boot ID: %w", err)
	}
	return strings.TrimSpace(string(host)), strings.TrimSpace(string(boot)), nil
}
