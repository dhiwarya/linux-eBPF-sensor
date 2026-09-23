// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Docker talks to the Docker Engine API over its unix socket. Only the few
// endpoints the sensor needs are implemented, to avoid the full SDK.
type Docker struct {
	socket string
	http   *http.Client // for request/response calls, with a timeout
	stream *http.Client // for the event stream, without a timeout

	mu           sync.Mutex
	cgroupDriver string // cached after the first successful /info call
}

// NewDocker returns a client for the socket, usually /var/run/docker.sock.
func NewDocker(socket string) *Docker {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Docker{
		socket: socket,
		http:   &http.Client{Transport: tr, Timeout: 10 * time.Second},
		stream: &http.Client{Transport: tr},
	}
}

type dockerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"` // image ID
	State struct {
		Running bool `json:"Running"`
		Pid     int  `json:"Pid"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type dockerSummary struct {
	ID string `json:"Id"`
}

func (d *Docker) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("docker %s: %w", path, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// ErrNotFound is returned when a container does not exist.
var ErrNotFound = errors.New("not found")

// List implements Runtime.
func (d *Docker) List(ctx context.Context) ([]Container, error) {
	var sum []dockerSummary
	if err := d.get(ctx, "/containers/json?all=1", &sum); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(sum))
	for _, s := range sum {
		c, err := d.Inspect(ctx, s.ID)
		if errors.Is(err, ErrNotFound) {
			continue // removed since the list call
		}
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Inspect implements Runtime.
func (d *Docker) Inspect(ctx context.Context, idOrName string) (Container, error) {
	var in dockerInspect
	if err := d.get(ctx, "/containers/"+url.PathEscape(idOrName)+"/json", &in); err != nil {
		return Container{}, err
	}
	return Container{
		ID:      in.ID,
		Name:    strings.TrimPrefix(in.Name, "/"),
		Image:   in.Config.Image,
		ImageID: in.Image,
		Labels:  in.Config.Labels,
		Pid:     in.State.Pid,
		Running: in.State.Running,
	}, nil
}

// Events implements Runtime.
func (d *Docker) Events(ctx context.Context) (<-chan Event, <-chan error) {
	out := make(chan Event, 64)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		filters := url.QueryEscape(`{"type":["container"],"event":["create","start","die","destroy","rename"]}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/events?filters="+filters, nil)
		if err != nil {
			errc <- err
			return
		}
		resp, err := d.stream.Do(req)
		if err != nil {
			errc <- fmt.Errorf("docker events: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errc <- fmt.Errorf("docker events: %s", resp.Status)
			return
		}
		dec := json.NewDecoder(resp.Body)
		for {
			var m struct {
				Action string `json:"Action"`
				Actor  struct {
					ID string `json:"ID"`
				} `json:"Actor"`
			}
			if err := dec.Decode(&m); err != nil {
				if ctx.Err() == nil {
					errc <- fmt.Errorf("docker events: %w", err)
				}
				return
			}
			select {
			case out <- Event{Kind: EventKind(m.Action), ID: m.Actor.ID}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// CgroupPath implements Runtime. With the systemd cgroup driver (Ubuntu's
// default) Docker uses /system.slice/docker-<id>.scope; with cgroupfs,
// /docker/<id>.
func (d *Docker) CgroupPath(ctx context.Context, id string) (string, error) {
	driver, err := d.driver(ctx)
	if err != nil {
		return "", err
	}
	switch driver {
	case "systemd":
		return "/system.slice/docker-" + id + ".scope", nil
	case "cgroupfs":
		return "/docker/" + id, nil
	default:
		return "", fmt.Errorf("unsupported docker cgroup driver %q", driver)
	}
}

// driver returns Docker's cgroup driver. Only success is cached, so a daemon
// that is briefly unavailable does not break resolution for good.
func (d *Docker) driver(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cgroupDriver != "" {
		return d.cgroupDriver, nil
	}
	var info struct {
		CgroupDriver  string `json:"CgroupDriver"`
		CgroupVersion string `json:"CgroupVersion"`
	}
	if err := d.get(ctx, "/info", &info); err != nil {
		return "", err
	}
	if info.CgroupVersion != "2" {
		return "", fmt.Errorf("docker reports cgroup v%s; only cgroup v2 is supported", info.CgroupVersion)
	}
	d.cgroupDriver = info.CgroupDriver
	return d.cgroupDriver, nil
}
