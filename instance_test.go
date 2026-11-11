package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/uetam3/oncedrop/internal/server"
	"github.com/uetam3/oncedrop/internal/share"
)

func TestRequireLoopback(t *testing.T) {
	for _, a := range []string{"127.0.0.1:1", "localhost:1", "[::1]:1"} {
		if err := requireLoopback(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"0.0.0.0:1", "192.168.1.5:1", "example.com:1"} {
		if requireLoopback(a) == nil {
			t.Errorf("%s accepted", a)
		}
	}
}

// startOn serves h on a fresh loopback port and returns its address. h is
// built after the address is known, because the admin handler checks Host.
func startOn(t *testing.T, h func(addr string) http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()
	srv.Config.Handler = h(addr)
	srv.Start()
	t.Cleanup(srv.Close)
	return addr
}

func realAdmin(secret string) func(string) http.Handler {
	return func(addr string) http.Handler {
		return server.NewAdmin(share.NewStore(), nil, fstest.MapFS{}, log.New(io.Discard, "", 0), addr, secret, time.Minute, 1<<20).Handler()
	}
}

const instSecret = "0123456789abcdef0123456789abcdef0123456789a"

func TestCheckInstance(t *testing.T) {
	t.Run("same key", func(t *testing.T) {
		addr := startOn(t, realAdmin(instSecret))
		ok, err := checkInstance(addr, instSecret)
		if !ok || err != nil {
			t.Fatalf("got %v, %v", ok, err)
		}
	})
	t.Run("other key", func(t *testing.T) {
		addr := startOn(t, realAdmin(strings.Repeat("z", 43)))
		if ok, err := checkInstance(addr, instSecret); !ok || err == nil {
			t.Fatalf("got %v, %v; want running but refused", ok, err)
		}
	})
	t.Run("impostor", func(t *testing.T) {
		addr := startOn(t, func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(server.AppID + "\n"))
			})
		})
		if ok, err := checkInstance(addr, instSecret); !ok || err == nil {
			t.Fatalf("got %v, %v; want running but refused", ok, err)
		}
	})
	t.Run("unrelated", func(t *testing.T) {
		addr := startOn(t, func(string) http.Handler { return http.NotFoundHandler() })
		if ok, err := checkInstance(addr, instSecret); ok || err != nil {
			t.Fatalf("got %v, %v; want not running", ok, err)
		}
	})
}

// An impostor holding the port must never see the key or a file.
func TestHandOverRefusesImpostor(t *testing.T) {
	var leaked atomic.Bool
	addr := startOn(t, func(string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" || strings.Contains(r.Header.Get("Cookie"), instSecret) {
				leaked.Store(true)
			}
			_, _ = w.Write([]byte(server.AppID + "\n"))
		})
	})
	f := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(f, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := handOver(context.Background(), addr, instSecret, []string{f}, time.Minute, false, false); err == nil {
		t.Fatal("handOver succeeded against an impostor")
	}
	if leaked.Load() {
		t.Fatal("impostor received more than the health check")
	}
}

func TestHandOverOpensOneTimeLink(t *testing.T) {
	addr := startOn(t, realAdmin(instSecret))
	var opened string
	orig := openBrowser
	openBrowser = func(u string) { opened = u }
	t.Cleanup(func() { openBrowser = orig })
	if err := handOver(context.Background(), addr, instSecret, nil, time.Minute, false, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(opened, instSecret) || !strings.HasPrefix(opened, "http://"+addr+"/?c=") {
		t.Fatalf("opened %q", opened)
	}
}
