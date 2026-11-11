// Package server hosts the two HTTP faces of the app: the local admin panel
// (127.0.0.1 only) and the public receiver reachable through the tunnel.
package server

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

// AppID identifies this program to its own clients: it is the /healthz marker
// and the value of the X-Requested-With header the admin panel requires.
const AppID = "oncedrop"

// CookieName is the admin cookie name for a panel listening on host. Cookies
// are not isolated by port, so the name carries the address.
func CookieName(host string) string {
	return "od_admin_" + strings.NewReplacer(".", "_", ":", "_").Replace(host)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// servePage writes one of the embedded HTML entry points.
func servePage(dist fs.FS, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(dist, name)
		if err != nil {
			http.Error(w, "frontend not built: run `npm run build` in web/", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	}
}

// assets serves Vite's hashed bundles. They are immutable, so long cache.
func assets(dist fs.FS) http.Handler {
	fsrv := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fsrv.ServeHTTP(w, r)
	})
}

// secureHeaders is applied to every response on both listeners.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; "+
				"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
