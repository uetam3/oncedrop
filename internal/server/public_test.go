package server

import (
	"encoding/json"
	"fmt"
	"github.com/uetam3/oncedrop/internal/share"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBlobOnce(t *testing.T) {
	_, store, h := newTestPublic(t)
	sh, _ := store.Create(share.Header{Name: "f.txt"}, []byte("secret"), time.Minute)
	get := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/s/"+sh.Token+"/blob", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := get()
	if w.Code != 200 || w.Body.String() != string(sh.Cipher) {
		t.Fatalf("first: %d", w.Code)
	}
	w = get()
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 410 || body["reason"] != "consumed" {
		t.Fatalf("second: %d %v", w.Code, body)
	}
}

func TestRateLimit(t *testing.T) {
	_, _, h := newTestPublic(t)
	for i := 0; i < 30; i++ {
		r := httptest.NewRequest("GET", "/api/s/nope", nil)
		r.RemoteAddr = "9.9.9.9:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/api/s/nope", nil)
	r.RemoteAddr = "9.9.9.9:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "600" {
		t.Fatalf("31st: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestRootNotFound(t *testing.T) {
	_, _, h := newTestPublic(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 404 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name, provider string
		hdr            map[string]string
		want           string
	}{
		{"cloudflared", "cloudflared", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "1.2.3.4"},
		{"lhr last xff", "localhost.run", map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "6.6.6.6, 5.5.5.5"}, "5.5.5.5"},
		{"lhr bare", "localhost.run", nil, "127.0.0.1"},
		{"none ignores xff", "none", map[string]string{"X-Forwarded-For": "6.6.6.6"}, "127.0.0.1"},
		{"empty provider", "", map[string]string{"CF-Connecting-IP": "6.6.6.6"}, "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "127.0.0.1:5000"
			for k, v := range c.hdr {
				r.Header.Set(k, v)
			}
			if got := clientIP(r, c.provider); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestLimiterBoundedKeys(t *testing.T) {
	l := newLimiter(1, time.Hour)
	l.maxKeys = 3
	for i := 0; i < 100; i++ {
		l.hit(fmt.Sprintf("k%d", i))
	}
	if len(l.counts) > 4 {
		t.Fatalf("keys = %d", len(l.counts))
	}
	if l.allow("fresh-key") {
		t.Fatal("fresh key escapes the overflow bucket")
	}
}

func TestRateLimitSpoofedHeaderLocalhostRun(t *testing.T) {
	_, _, h := newTestPublicWith(t, "localhost.run")
	do := func(i int) int {
		r := httptest.NewRequest("GET", "/api/s/nope", nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("CF-Connecting-IP", fmt.Sprintf("10.0.0.%d", i))
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.0.%d, 5.5.5.5", i))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 30; i++ {
		if c := do(i); c != 404 {
			t.Fatalf("request %d: %d", i, c)
		}
	}
	if c := do(31); c != 429 {
		t.Fatalf("31st: %d", c)
	}
}
