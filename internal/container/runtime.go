// SPDX-License-Identifier: Apache-2.0

// Package container resolves the target container, maps it to its cgroup v2
// ID and keeps the kernel's target_cgroups map up to date as it restarts.
package container

import (
	"context"
	"fmt"
	"strings"
)

// Container is the metadata used for enrichment and cgroup resolution.
type Container struct {
	ID      string
	Name    string // without the leading '/'
	Image   string // as configured, e.g. "alpine:3.20"
	ImageID string
	Labels  map[string]string
	Pid     int // host PID of the container's init process, 0 if not running
	Running bool
}

// Target selects the one container to capture. Exactly one field is set.
type Target struct {
	Name  string
	ID    string // full ID or unique prefix
	Label string // "key=value"
}

func (t Target) String() string {
	switch {
	case t.Name != "":
		return "name=" + t.Name
	case t.ID != "":
		return "id=" + t.ID
	default:
		return "label=" + t.Label
	}
}

// Validate checks that exactly one selector is set.
func (t Target) Validate() error {
	n := 0
	for _, s := range []string{t.Name, t.ID, t.Label} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("target: set exactly one of name, id or label (got %d)", n)
	}
	if t.Label != "" && !strings.Contains(t.Label, "=") {
		return fmt.Errorf("target: label must be key=value, got %q", t.Label)
	}
	return nil
}

// Matches reports whether c is the target.
func (t Target) Matches(c Container) bool {
	switch {
	case t.Name != "":
		return c.Name == strings.TrimPrefix(t.Name, "/")
	case t.ID != "":
		return strings.HasPrefix(c.ID, t.ID)
	default:
		k, v, _ := strings.Cut(t.Label, "=")
		got, ok := c.Labels[k]
		return ok && got == v
	}
}

// EventKind is a container lifecycle change.
type EventKind string

const (
	EventCreate  EventKind = "create"
	EventStart   EventKind = "start"
	EventDie     EventKind = "die"
	EventDestroy EventKind = "destroy"
	EventRename  EventKind = "rename"
)

// Event is a lifecycle change reported by the runtime.
type Event struct {
	Kind EventKind
	ID   string
}

// Runtime is a container runtime. Docker is implemented; containerd can be
// added behind the same interface.
type Runtime interface {
	// List returns all containers, running or not.
	List(ctx context.Context) ([]Container, error)
	// Inspect returns one container by ID or name.
	Inspect(ctx context.Context, idOrName string) (Container, error)
	// Events streams lifecycle events until ctx is done or the stream fails.
	Events(ctx context.Context) (<-chan Event, <-chan error)
	// CgroupPath returns the cgroup v2 path, relative to the cgroup root,
	// that the runtime creates for container id, e.g.
	// /system.slice/docker-<id>.scope.
	CgroupPath(ctx context.Context, id string) (string, error)
}
