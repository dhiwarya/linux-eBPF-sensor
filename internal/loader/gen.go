// SPDX-License-Identifier: Apache-2.0

// Package loader loads the sensor's BPF programs, attaches them and exposes
// decoded events.
package loader

//go:generate go tool bpf2go -target amd64,arm64 -type event -type exec_event -type event_type -type drop_reason process ../../bpf/process.bpf.c -- -I../../bpf -I../../bpf/headers -O2 -g -Wall -Werror
