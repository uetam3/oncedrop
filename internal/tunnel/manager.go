package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// State of the on-demand tunnel as shown in the admin panel.
const (
	StateIdle     = "idle"     // nobody needs it, nothing is exposed
	StateStarting = "starting" // connecting or reconnecting
	StateUp       = "up"
	StateError    = "error" // last attempt failed, retrying with backoff
)

// Status is a snapshot for the UI.
type Status struct {
	State    string `json:"state"`
	URL      string `json:"url,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Verified is true once a request through the public URL came back to
	// this process. A fresh trycloudflare hostname takes a few seconds.
	Verified bool      `json:"verified"`
	Err      string    `json:"err,omitempty"`
	Since    time.Time `json:"since"`
}

// Manager keeps a tunnel open only while something needs it: the admin
// panel is open (Touch), or Hold reports pending shares or transfers. When
// demand disappears for Idle, the tunnel is closed; the next Touch opens a
// new one. A tunnel that stops answering its own health probe is replaced.
type Manager struct {
	Provider string
	Port     int
	Idle     time.Duration
	Log      *log.Logger
	// Hold reports demand that does not come from the panel.
	Hold func() bool
	// ProbePath returns the path the public server echoes for a nonce
	// (see server.Public). Nil disables probing.
	ProbePath func(nonce string) string

	mu         sync.Mutex
	st         Status
	lastDemand time.Time
	changed    chan struct{} // closed and replaced on every state change
	wake       chan struct{}
}

func (m *Manager) init() {
	if m.changed == nil {
		m.changed = make(chan struct{})
		m.wake = make(chan struct{}, 1)
		m.st = Status{State: StateIdle, Since: time.Now()}
	}
}

// Touch records demand and starts the tunnel if it is idle.
func (m *Manager) Touch() {
	m.mu.Lock()
	m.init()
	m.lastDemand = time.Now()
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	return m.st
}

// URL is the current public base URL, or "" when the tunnel is not up.
func (m *Manager) URL() string {
	s := m.Status()
	if s.State != StateUp {
		return ""
	}
	return s.URL
}

// WaitURL touches the tunnel and blocks until it is up (preferably
// verified, but no longer than verifyWait after it came up).
func (m *Manager) WaitURL(ctx context.Context) (string, error) {
	const verifyWait = 20 * time.Second
	for {
		m.Touch()
		m.mu.Lock()
		st, ch := m.st, m.changed
		m.mu.Unlock()
		if st.State == StateUp && (st.Verified || m.ProbePath == nil || time.Since(st.Since) > verifyWait) {
			return st.URL, nil
		}
		var timer <-chan time.Time
		if st.State == StateUp {
			timer = time.After(verifyWait - time.Since(st.Since))
		}
		select {
		case <-ctx.Done():
			if st.Err != "" {
				return "", fmt.Errorf("tunnel: %s", st.Err)
			}
			return "", fmt.Errorf("tunnel is not up yet")
		case <-ch:
		case <-timer:
		}
	}
}

func (m *Manager) set(f func(*Status)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.st.State
	f(&m.st)
	if m.st.State != prev {
		m.st.Since = time.Now()
	}
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *Manager) wanted() bool {
	m.mu.Lock()
	recent := time.Since(m.lastDemand) < m.Idle
	m.mu.Unlock()
	return recent || (m.Hold != nil && m.Hold())
}

// Run drives the tunnel until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.init()
	m.mu.Unlock()
	backoff := time.Duration(0)
	for {
		// Idle: wait for demand.
		for !m.wanted() {
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
			case <-time.After(5 * time.Second):
			}
		}

		m.set(func(s *Status) { s.State = StateStarting })
		m.Log.Printf("opening %s tunnel to 127.0.0.1:%d", m.Provider, m.Port)
		startCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		tun, err := Start(startCtx, m.Provider, m.Port)
		cancel()
		if ctx.Err() != nil {
			if tun != nil {
				tun.Close()
			}
			return
		}
		if err != nil {
			backoff = min(max(backoff*2, 5*time.Second), 2*time.Minute)
			m.Log.Printf("tunnel failed: %v (retry in %s)", err, backoff)
			m.set(func(s *Status) { *s = Status{State: StateError, Err: err.Error(), Since: s.Since} })
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		m.Log.Printf("tunnel up: %s (%s)", tun.URL(), tun.Provider())
		m.set(func(s *Status) {
			*s = Status{State: StateUp, URL: tun.URL(), Provider: tun.Provider(), Since: s.Since}
		})

		reason := m.supervise(ctx, tun)
		tun.Close()
		if ctx.Err() != nil {
			return
		}
		if reason == "" {
			m.Log.Printf("tunnel closed: idle")
			m.set(func(s *Status) { *s = Status{State: StateIdle, Since: s.Since} })
		} else {
			m.Log.Printf("tunnel lost: %s; reconnecting (old links are invalid)", reason)
			m.set(func(s *Status) { *s = Status{State: StateStarting, Err: reason, Since: s.Since} })
		}
	}
}

// supervise watches a live tunnel. It returns "" when the tunnel should be
// closed for lack of demand, or the reason it has to be replaced.
func (m *Manager) supervise(ctx context.Context, tun Tunnel) string {
	verified := false
	failures := 0
	nextProbe := time.Now()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return "shutdown"
		case <-tun.Done():
			return fmt.Sprint(tun.Err())
		case <-tick.C:
		}
		if !m.wanted() {
			return ""
		}
		if m.ProbePath == nil || tun.Provider() == ProviderNone || time.Now().Before(nextProbe) {
			continue
		}
		err := m.probe(ctx, tun.URL())
		switch {
		case err == nil:
			failures = 0
			nextProbe = time.Now().Add(time.Minute)
			if !verified {
				verified = true
				m.Log.Printf("tunnel verified end to end")
				m.set(func(s *Status) { s.Verified = true })
			}
		case !verified:
			// New hostnames need a moment to resolve. Keep trying for a
			// while, then accept the tunnel unverified: the local network
			// may simply not be able to reach its own public URL.
			up := time.Since(m.Status().Since)
			if up > 2*time.Minute {
				m.Log.Printf("tunnel could not be verified from this machine: %v", err)
				nextProbe = time.Now().Add(time.Hour * 24 * 365)
			} else {
				nextProbe = time.Now().Add(2 * time.Second)
			}
		default:
			failures++
			nextProbe = time.Now().Add(15 * time.Second)
			if failures >= 3 {
				return "health check failed: " + err.Error()
			}
		}
	}
}

// probe asks the public URL to echo a random nonce back.
func (m *Manager) probe(ctx context.Context, base string) error {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+m.ProbePath(nonce), nil)
	if err != nil {
		return err
	}
	res, err := probeClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 256))
	if res.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != nonce {
		return fmt.Errorf("probe got HTTP %d", res.StatusCode)
	}
	return nil
}

// probeClient resolves through 1.1.1.1 first: the system resolver (WSL in
// particular) tends to cache the NXDOMAIN of a hostname looked up before
// Cloudflare published it.
var probeClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if ips, err := publicResolver.LookupHost(ctx, host); err == nil {
				for _, ip := range ips {
					if c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
						return c, nil
					}
				}
			}
			return d.DialContext(ctx, network, addr)
		},
	},
}

var publicResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(ctx, network, "1.1.1.1:53")
	},
}
