// Package tunnel exposes a local TCP port to the internet through a free,
// login-free provider.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"

	"github.com/uetam3/oncedrop/internal/cfbin"
)

// Tunnel is a running public endpoint for a local port.
type Tunnel interface {
	// URL is the public https base URL, without trailing slash.
	URL() string
	// Done is closed when the tunnel dies; Err then reports why.
	Done() <-chan struct{}
	Err() error
	Close() error
	Provider() string
}

const (
	ProviderAuto         = "auto"
	ProviderCloudflared  = "cloudflared"
	ProviderLocalhostRun = "localhost.run"
	ProviderNone         = "none"
)

// cloudflaredPath prefers the copy embedded in this executable and falls
// back to one in PATH.
func cloudflaredPath() (string, error) {
	p, err := cfbin.Path()
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, cfbin.ErrNotEmbedded) {
		log.Printf("embedded cloudflared unusable: %v", err)
	}
	if p, err := exec.LookPath("cloudflared"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("cloudflared is neither embedded nor in PATH (use -tunnel localhost.run)")
}

// Start opens a tunnel to 127.0.0.1:port using the requested provider.
// "auto" uses cloudflared when available and falls back to localhost.run,
// which needs nothing but an outbound SSH port.
func Start(ctx context.Context, provider string, port int) (Tunnel, error) {
	switch provider {
	case ProviderAuto:
		if bin, err := cloudflaredPath(); err == nil {
			t, err := startCloudflared(ctx, bin, port)
			if err == nil || ctx.Err() != nil {
				return t, err
			}
			log.Printf("cloudflared failed (%v), trying localhost.run", err)
		}
		return startLocalhostRun(ctx, port)
	case ProviderCloudflared:
		bin, err := cloudflaredPath()
		if err != nil {
			return nil, err
		}
		return startCloudflared(ctx, bin, port)
	case ProviderLocalhostRun:
		return startLocalhostRun(ctx, port)
	case ProviderNone:
		return &noTunnel{url: fmt.Sprintf("http://127.0.0.1:%d", port)}, nil
	}
	return nil, fmt.Errorf("unknown tunnel provider %q", provider)
}

// ValidProvider reports whether name is accepted by Start.
func ValidProvider(name string) bool {
	switch name {
	case ProviderAuto, ProviderCloudflared, ProviderLocalhostRun, ProviderNone:
		return true
	}
	return false
}

type noTunnel struct {
	url string
}

func (n *noTunnel) URL() string           { return n.url }
func (n *noTunnel) Done() <-chan struct{} { return nil }
func (n *noTunnel) Err() error            { return nil }
func (n *noTunnel) Close() error          { return nil }
func (n *noTunnel) Provider() string      { return ProviderNone }
