# SPDX-License-Identifier: Apache-2.0

BINARY    := anyone-sensor
GO        ?= go
ARCH      := $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
VMLINUX   := bpf/headers/vmlinux_$(ARCH).h
BPFTOOL   ?= bpftool
SENSOR_ARGS ?=

.PHONY: all vmlinux generate build run test e2e lint clean

all: build

## vmlinux: dump vmlinux.h for the running kernel's architecture from its BTF.
## The other architecture's header is vendored (see bpf/headers/vmlinux.h).
vmlinux:
	@echo "/* SPDX-License-Identifier: GPL-2.0-only */" > $(VMLINUX)
	@echo "/* Generated from Linux kernel BTF: $$(uname -r) $$(uname -m) */" >> $(VMLINUX)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c >> $(VMLINUX)

## generate: compile BPF C and regenerate the bpf2go Go bindings (requires clang).
generate:
	$(GO) generate ./...

## build: build the sensor binary from committed bpf2go output (no clang needed).
build:
	CGO_ENABLED=0 $(GO) build -o $(BINARY) ./cmd/anyone-sensor

run: build
	sudo ./$(BINARY) $(SENSOR_ARGS)

test:
	$(GO) test ./...

e2e: build
	@for s in test/e2e/*.sh; do [ -e "$$s" ] || continue; echo "== $$s"; sudo "$$s" || exit 1; done

lint:
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "golangci-lint not installed; ran go vet only"

clean:
	rm -f $(BINARY)
