package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"github.com/uetam3/oncedrop/internal/share"
	"github.com/uetam3/oncedrop/internal/tunnel"
)

const (
	testHost   = "127.0.0.1:47651"
	testSecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)

func testDist() fstest.MapFS {
	return fstest.MapFS{
		"admin.html":   {Data: []byte("<html>admin</html>")},
		"receive.html": {Data: []byte("<html>recv</html>")},
	}
}

func newTestAdmin(t *testing.T, maxSize int64) (*Admin, http.Handler) {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	m := &tunnel.Manager{Provider: tunnel.ProviderNone, Port: 1, Idle: time.Minute, Log: logger}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go m.Run(ctx)
	a := NewAdmin(share.NewStore(), m, testDist(), logger, testHost, testSecret, 15*time.Minute, maxSize)
	return a, a.Handler()
}

func authedRequest(method, target string, body io.Reader) *http.Request {
	r, _ := http.NewRequest(method, target, body)
	r.Host = testHost
	r.AddCookie(&http.Cookie{Name: CookieName(testHost), Value: testSecret})
	r.Header.Set("X-Requested-With", AppID)
	return r
}

func newTestPublic(t *testing.T) (*Public, *share.Store, http.Handler) {
	return newTestPublicWith(t, tunnel.ProviderNone)
}

func newTestPublicWith(t *testing.T, provider string) (*Public, *share.Store, http.Handler) {
	t.Helper()
	store := share.NewStore()
	p := NewPublic(store, testDist(), log.New(io.Discard, "", 0), func() string { return provider })
	return p, store, p.Handler()
}
