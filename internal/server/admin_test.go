package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStateGuard(t *testing.T) {
	_, h := newTestAdmin(t, 1<<20)
	cases := []struct {
		name string
		mod  func(r *http.Request)
		want int
	}{
		{"bad host", func(r *http.Request) { r.Host = "evil.com" }, 403},
		{"no cookie", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"no xrw", func(r *http.Request) { r.Header.Del("X-Requested-With") }, 403},
		{"bad origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil.com") }, 403},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"ok", func(r *http.Request) {}, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := authedRequest("GET", "/api/state", nil)
			c.mod(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("got %d want %d", w.Code, c.want)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	_, h := newTestAdmin(t, 1<<20)
	r := httptest.NewRequest("GET", "/?k=wrong", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("wrong key: %d", w.Code)
	}
	r = httptest.NewRequest("GET", "/?k="+testSecret, nil)
	r.Host = testHost
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("login: %d %q", w.Code, w.Header().Get("Location"))
	}
	c := w.Header().Get("Set-Cookie")
	if !containsAll(c, "HttpOnly", "SameSite=Strict") {
		t.Fatalf("cookie: %s", c)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

func multipartBody(t *testing.T, fileSize int, ttl string, ttlFirst bool) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	writeTTL := func() {
		if ttl != "" {
			_ = mw.WriteField("ttlSec", ttl)
		}
	}
	if ttlFirst {
		writeTTL()
	}
	if fileSize >= 0 {
		fw, _ := mw.CreateFormFile("file", "big.bin")
		_, _ = fw.Write(bytes.Repeat([]byte("a"), fileSize))
	}
	if !ttlFirst {
		writeTTL()
	}
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestCreateDoesNotSpoolToDisk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("TMPDIR is not honoured on Windows")
	}
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	_, h := newTestAdmin(t, 40<<20)
	body, ct := multipartBody(t, 33<<20, "60", false)
	r := authedRequest("POST", "/api/share", body)
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("plaintext spooled to disk: %d entries", len(ents))
	}
	var v struct {
		ExpiresAt time.Time `json:"expiresAt"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if d := time.Until(v.ExpiresAt); d < 55*time.Second || d > 65*time.Second {
		t.Fatalf("ttl not honoured: %s", d)
	}
}

func TestCreateTooLarge(t *testing.T) {
	_, h := newTestAdmin(t, 1024)
	body, ct := multipartBody(t, 2048, "", false)
	r := authedRequest("POST", "/api/share", body)
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestCreateMissingFile(t *testing.T) {
	_, h := newTestAdmin(t, 1024)
	body, ct := multipartBody(t, -1, "60", true)
	r := authedRequest("POST", "/api/share", body)
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("got %d", w.Code)
	}
}

func loginWith(h http.Handler, query string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/?"+query, nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The browser opener's command line is visible to other local users, so it
// gets a single-use, short-lived code instead of the panel key.
func TestOneTimeLogin(t *testing.T) {
	a, h := newTestAdmin(t, 1<<20)
	u := a.OneTimeLoginURL()
	if strings.Contains(u, testSecret) || !strings.HasPrefix(u, "http://"+testHost+"/?c=") {
		t.Fatalf("bad url %q", u)
	}
	q := strings.SplitN(u, "?", 2)[1]
	w := loginWith(h, q)
	if w.Code != 303 || !strings.Contains(w.Header().Get("Set-Cookie"), testSecret) {
		t.Fatalf("first use: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	if w := loginWith(h, q); w.Code != 403 || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("second use: %d", w.Code)
	}
	if w := loginWith(h, "c=nope"); w.Code != 403 {
		t.Fatalf("unknown code: %d", w.Code)
	}
}

func TestOneTimeLoginExpires(t *testing.T) {
	a, h := newTestAdmin(t, 1<<20)
	q := strings.SplitN(a.OneTimeLoginURL(), "?", 2)[1]
	a.mu.Lock()
	for c := range a.codes {
		a.codes[c] = time.Now().Add(-time.Second)
	}
	a.mu.Unlock()
	if w := loginWith(h, q); w.Code != 403 {
		t.Fatalf("expired code: %d", w.Code)
	}
}

func TestLoginLinkAPI(t *testing.T) {
	_, h := newTestAdmin(t, 1<<20)
	r := authedRequest("POST", "/api/login-link", nil)
	r.Header.Del("Cookie")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, authedRequest("POST", "/api/login-link", nil))
	var out struct{ URL string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := loginWith(h, strings.SplitN(out.URL, "?", 2)[1]); w.Code != 303 {
		t.Fatalf("link from API: %d", w.Code)
	}
}
