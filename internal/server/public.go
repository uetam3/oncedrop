package server

import (
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uetam3/oncedrop/internal/share"
	"github.com/uetam3/oncedrop/internal/tunnel"
)

// Public is the face exposed through the tunnel. It knows nothing about
// file names or keys: it serves the receiver page and opaque ciphertext.
type Public struct {
	store *share.Store
	dist  fs.FS
	log   *log.Logger
	// OnDownload is called after a share was consumed (for the terminal UI).
	OnDownload func(sh *share.Share)

	inflight atomic.Int32
	misses   *limiter
	provider func() string
}

func NewPublic(store *share.Store, dist fs.FS, logger *log.Logger, provider func() string) *Public {
	if provider == nil {
		provider = func() string { return "" }
	}
	return &Public{
		store: store, dist: dist, log: logger, provider: provider,
		// 128-bit tokens cannot be guessed anyway; this just keeps scanners
		// from hammering the machine through the tunnel.
		misses: newLimiter(30, 10*time.Minute),
	}
}

// ProbePrefix is where the tunnel manager checks that the public URL
// reaches this process.
const ProbePrefix = "/_probe/"

// ProbePath is the path that echoes nonce.
func ProbePath(nonce string) string { return ProbePrefix + nonce }

// Busy reports whether a ciphertext is being sent right now, so the tunnel
// must not be closed under it.
func (p *Public) Busy() bool { return p.inflight.Load() > 0 }

func (p *Public) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /s/{token}", servePage(p.dist, "receive.html"))
	mux.HandleFunc("GET /api/s/{token}", p.limited(p.status))
	mux.HandleFunc("GET /api/s/{token}/blob", p.limited(p.blob))
	mux.HandleFunc("GET "+ProbePrefix+"{nonce}", probe)
	mux.Handle("GET /assets/", assets(p.dist))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Nothing to see at the root; do not advertise what this is.
		http.NotFound(w, r)
	})
	return secureHeaders(mux)
}

func probe(w http.ResponseWriter, r *http.Request) {
	n := r.PathValue("nonce")
	if len(n) != 32 || strings.Trim(n, "0123456789abcdef") != "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(n))
}

// limited rejects clients that produced too many unknown/dead-token
// answers recently.
func (p *Public) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.misses.allow(p.clientIP(r)) {
			w.Header().Set("Retry-After", "600")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "reason": "rate_limited"})
			return
		}
		h(w, r)
	}
}

func statusOf(err error) (int, string) {
	switch {
	case errors.Is(err, share.ErrConsumed):
		return http.StatusGone, "consumed"
	case errors.Is(err, share.ErrExpired):
		return http.StatusGone, "expired"
	default:
		return http.StatusNotFound, "not_found"
	}
}

func (p *Public) fail(w http.ResponseWriter, r *http.Request, err error) {
	code, reason := statusOf(err)
	if code == http.StatusNotFound {
		p.misses.hit(p.clientIP(r))
	}
	writeJSON(w, code, map[string]any{"ok": false, "reason": reason})
}

func (p *Public) status(w http.ResponseWriter, r *http.Request) {
	sh, err := p.store.Status(r.PathValue("token"))
	if err != nil {
		p.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"cipherSize": len(sh.Cipher),
		"expiresAt":  sh.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (p *Public) blob(w http.ResponseWriter, r *http.Request) {
	p.inflight.Add(1)
	defer p.inflight.Add(-1)
	remote := p.clientIP(r)
	sh, err := p.store.Consume(r.PathValue("token"), remote)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.log.Printf("share %s downloaded by %s", sh.Token[:6], remote)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(sh.Cipher)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", "attachment; filename=\"blob.bin\"")
	_, _ = w.Write(sh.Cipher)
	if p.OnDownload != nil {
		p.OnDownload(sh)
	}
}

func (p *Public) clientIP(r *http.Request) string { return clientIP(r, p.provider()) }

// clientIP picks the client address according to who sits in front of us.
// Cloudflare's edge overwrites CF-Connecting-IP, so it can be trusted there.
// localhost.run appends the real address to X-Forwarded-For, so only the last
// element is trustworthy; earlier ones are client-controlled. With no tunnel
// the socket address is the only honest source.
func clientIP(r *http.Request, provider string) string {
	switch provider {
	case tunnel.ProviderCloudflared:
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			return v
		}
	case tunnel.ProviderLocalhostRun:
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			if i := strings.LastIndexByte(v, ','); i >= 0 {
				v = v[i+1:]
			}
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter counts events per key in a fixed window.
type limiter struct {
	max     int
	maxKeys int
	window  time.Duration

	mu     sync.Mutex
	counts map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func newLimiter(max int, win time.Duration) *limiter {
	return &limiter{max: max, maxKeys: 10000, window: win, counts: make(map[string]*window)}
}

// keyFor maps a key to itself, or to the shared overflow bucket when the
// table is full of live entries. Callers hold l.mu.
func (l *limiter) keyFor(key string, now time.Time) string {
	if _, ok := l.counts[key]; ok {
		return key
	}
	if len(l.counts) >= l.maxKeys {
		for k, w := range l.counts {
			if now.Sub(w.start) > l.window {
				delete(l.counts, k)
			}
		}
	}
	if len(l.counts) >= l.maxKeys {
		return "overflow"
	}
	return key
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.counts[l.keyFor(key, time.Now())]
	return w == nil || time.Since(w.start) > l.window || w.n < l.max
}

func (l *limiter) hit(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	key = l.keyFor(key, now)
	w := l.counts[key]
	if w == nil || now.Sub(w.start) > l.window {
		w = &window{start: now}
		l.counts[key] = w
	}
	w.n++
}
