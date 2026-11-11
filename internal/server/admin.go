package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/uetam3/oncedrop/internal/share"
	"github.com/uetam3/oncedrop/internal/tunnel"
)

// Admin is the local control panel. It binds to 127.0.0.1 only and is
// additionally guarded against browser cross-site abuse (DNS rebinding,
// CSRF) by a Host check and a custom request header requirement, and
// against other local users/processes by a secret: the first visit carries
// it in ?k=, after which it lives in an HttpOnly cookie.
type Admin struct {
	store   *share.Store
	tun     *tunnel.Manager
	dist    fs.FS
	log     *log.Logger
	host    string // exact Host header we accept, e.g. 127.0.0.1:43111
	secret  string
	cookie  string
	ttl     time.Duration
	maxSize int64

	mu    sync.Mutex
	codes map[string]time.Time // one-time login codes -> expiry
}

func NewAdmin(store *share.Store, tun *tunnel.Manager, dist fs.FS, logger *log.Logger, host, secret string, ttl time.Duration, maxSize int64) *Admin {
	return &Admin{
		store: store, tun: tun, dist: dist, log: logger,
		host: host, secret: secret,
		cookie: CookieName(host),
		ttl:    ttl, maxSize: maxSize,
		codes: make(map[string]time.Time),
	}
}

// LoginURL is the address to open the panel with (it sets the cookie).
func (a *Admin) LoginURL() string {
	return "http://" + a.host + "/?k=" + a.secret
}

// loginCodeTTL bounds how long a one-time login link stays usable.
const loginCodeTTL = 2 * time.Minute

// OneTimeLoginURL is a panel link for opening in a browser: it logs in once,
// within loginCodeTTL. Unlike LoginURL it is safe to pass on a command line,
// which other local users can read while the process runs.
func (a *Admin) OneTimeLoginURL() string {
	code := rand.Text()
	now := time.Now()
	a.mu.Lock()
	for c, exp := range a.codes {
		if now.After(exp) {
			delete(a.codes, c)
		}
	}
	a.codes[code] = now.Add(loginCodeTTL)
	a.mu.Unlock()
	return "http://" + a.host + "/?c=" + code
}

// useCode consumes a one-time login code.
func (a *Admin) useCode(code string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.codes[code]
	delete(a.codes, code)
	return ok && time.Now().Before(exp)
}

// ShareURL builds the full link the phone opens, or "" while the tunnel is
// down. The key rides in the URL fragment, which browsers never send to the
// server or the tunnel.
func (a *Admin) ShareURL(sh *share.Share) string {
	base := a.tun.URL()
	if base == "" {
		return ""
	}
	return base + "/s/" + sh.Token + "#" + sh.KeyParam()
}

func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.page)
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.Handle("GET /assets/", assets(a.dist))
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/login-link", a.loginLink)
	mux.HandleFunc("POST /api/share", a.create)
	mux.HandleFunc("GET /api/share/{token}", a.get)
	mux.HandleFunc("POST /api/share/{token}/renew", a.renew)
	mux.HandleFunc("DELETE /api/share/{token}", a.remove)
	return secureHeaders(a.guard(mux))
}

// healthz identifies the program. With ?nonce= it also proves knowledge of
// the panel key, so a second copy never hands files or the key to some
// other process that grabbed the port first.
func (a *Admin) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	out := AppID + "\n"
	if n := r.URL.Query().Get("nonce"); n != "" && len(n) <= 128 {
		out += InstanceProof(a.secret, n) + "\n"
	}
	_, _ = w.Write([]byte(out))
}

// InstanceProof is HMAC-SHA256(secret, nonce), hex encoded, under a label
// that keeps it from being reused for anything else.
func InstanceProof(secret, nonce string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("oncedrop instance proof\x00" + nonce))
	return hex.EncodeToString(m.Sum(nil))
}

func (a *Admin) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != a.host {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !a.authed(r) {
				writeError(w, http.StatusUnauthorized, "not logged in: open the link printed in the terminal")
				return
			}
			// Cross-origin requests cannot set this header without a CORS
			// preflight, which we never answer.
			if r.Header.Get("X-Requested-With") != AppID {
				http.Error(w, "missing X-Requested-With", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+a.host {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
			if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
				http.Error(w, "cross-site request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Admin) authed(r *http.Request) bool {
	c, err := r.Cookie(a.cookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(a.secret)) == 1
}

// page serves the panel, logging the browser in when ?k= is right.
func (a *Admin) page(w http.ResponseWriter, r *http.Request) {
	k, c := r.URL.Query().Get("k"), r.URL.Query().Get("c")
	if k != "" || c != "" {
		if k != "" && subtle.ConstantTimeCompare([]byte(k), []byte(a.secret)) != 1 {
			a.log.Printf("admin: rejected login with a wrong secret")
			http.Error(w, "wrong key", http.StatusForbidden)
			return
		}
		if k == "" && !a.useCode(c) {
			http.Error(w, "this login link has expired or was already used: open the address printed in the terminal", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     a.cookie,
			Value:    a.secret,
			Path:     "/",
			MaxAge:   400 * 24 * 3600,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		// Drop the secret from the address bar and history.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !a.authed(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(loginPage))
		return
	}
	servePage(a.dist, "admin.html")(w, r)
}

const loginPage = `<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>oncedrop</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 16px">
<h1 style="font-size:20px">oncedrop</h1>
<p>The panel needs a key. Open the address printed in the terminal when the
program started (the one with <code>?k=</code>) or run <code>oncedrop</code> again.
The browser will remember the key.</p>
</body></html>`

// loginLink hands a fresh one-time login link to a second oncedrop
// process, which then opens it in the browser.
func (a *Admin) loginLink(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"url": a.OneTimeLoginURL()})
}

type shareView struct {
	share.Summary
	URL  string `json:"url"`
	QR   string `json:"qr"`   // data: URL, PNG
	Base string `json:"base"` // tunnel URL the link was built for
}

func (a *Admin) view(sh *share.Share) (shareView, error) {
	var sum share.Summary
	for _, s := range a.store.List() {
		if s.Token == sh.Token {
			sum = s
			break
		}
	}
	v := shareView{Summary: sum, Base: a.tun.URL(), URL: a.ShareURL(sh)}
	if v.URL == "" {
		return v, nil
	}
	png, err := qrcode.Encode(v.URL, qrcode.Medium, 512)
	if err != nil {
		return shareView{}, err
	}
	v.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	return v, nil
}

func (a *Admin) state(w http.ResponseWriter, r *http.Request) {
	// A visible panel is what keeps the tunnel open. Background tabs poll
	// without ?active=1 so a forgotten tab does not hold it forever.
	if r.URL.Query().Get("active") == "1" {
		a.tun.Touch()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnel":  a.tun.Status(),
		"idleSec": int(a.tun.Idle.Seconds()),
		"ttlSec":  int(a.ttl.Seconds()),
		"maxSize": a.maxSize,
		"shares":  a.store.List(),
	})
}

func (a *Admin) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, a.maxSize+1<<20)
	up, err := readUpload(r, a.maxSize)
	if errors.Is(err, errTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad upload: "+err.Error())
		return
	}
	ttl := a.ttl
	if v := up.TTLSec; v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil && d > 0 && d <= 24*time.Hour {
			ttl = d
		}
	}
	name, ctype, data := up.Name, up.Type, up.Data
	// Opening a tunnel takes a few seconds; the upload waits for it so the
	// response already carries a working link.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if _, err := a.tun.WaitURL(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	sh, err := a.store.Create(share.Header{Name: name, Type: ctype}, data, ttl)
	if errors.Is(err, share.ErrFull) {
		writeError(w, http.StatusInsufficientStorage, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Printf("share %s created for %q (%d bytes, ttl %s)", sh.Token[:6], name, len(data), ttl)
	v, err := a.view(sh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (a *Admin) get(w http.ResponseWriter, r *http.Request) {
	sh, err := a.store.Status(r.PathValue("token"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	v, err := a.view(sh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *Admin) renew(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if _, err := a.tun.WaitURL(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	sh, err := a.store.Renew(r.PathValue("token"), a.ttl)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, share.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeError(w, code, err.Error())
		return
	}
	a.log.Printf("share renewed as %s for %q", sh.Token[:6], sh.Header.Name)
	v, err := a.view(sh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (a *Admin) remove(w http.ResponseWriter, r *http.Request) {
	if !a.store.Delete(r.PathValue("token")) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
