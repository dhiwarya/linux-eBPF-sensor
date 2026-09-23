// SPDX-License-Identifier: Apache-2.0

module github.com/example/anyone-sensor

go 1.26.2

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/sys v0.48.0
)

tool github.com/cilium/ebpf/cmd/bpf2go
