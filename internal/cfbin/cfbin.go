// Package cfbin carries an optional, gzip-compressed cloudflared binary for
// the target platform inside the oncedrop executable.
//
// The release build (`make release`, see tools/release)
// stages exactly one file into bin/ before each `go build`:
//
//	bin/cloudflared.gz       gzip of the official release binary
//	bin/cloudflared.sha256   hex SHA-256 of the uncompressed binary
//	bin/cloudflared.version  upstream version string
//
// A plain `go build` embeds only bin/.keep and Path reports ErrNotEmbedded.
package cfbin

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

//go:embed all:bin
var files embed.FS

var ErrNotEmbedded = errors.New("cloudflared is not embedded in this build")

var (
	once    sync.Once
	path    string
	pathErr error
)

// Version is the embedded cloudflared version, or "" when none is embedded.
func Version() string {
	b, err := fs.ReadFile(files, "bin/cloudflared.version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Path unpacks the embedded binary into the user cache directory (once per
// process, and only if a verified copy is not already there) and returns
// its location.
func Path() (string, error) {
	once.Do(func() { path, pathErr = extract() })
	return path, pathErr
}

func extract() (string, error) {
	gz, err := fs.ReadFile(files, "bin/cloudflared.gz")
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotEmbedded
	}
	if err != nil {
		return "", err
	}
	sumHex, err := fs.ReadFile(files, "bin/cloudflared.sha256")
	if err != nil {
		return "", fmt.Errorf("embedded cloudflared has no checksum: %w", err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(sumHex)))
	if err != nil || len(want) != sha256.Size {
		return "", fmt.Errorf("embedded cloudflared checksum is malformed")
	}

	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	name := "cloudflared-" + Version() + "-" + hex.EncodeToString(want[:6])
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dst := filepath.Join(dir, name)

	if ok, _ := fileHasSum(dst, want); ok {
		return dst, nil
	}

	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".cloudflared-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), zr); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return "", fmt.Errorf("embedded cloudflared failed checksum verification")
	}
	if err := os.Chmod(tmp.Name(), 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		// Another instance may have won the race with an identical file.
		if ok, _ := fileHasSum(dst, want); ok {
			return dst, nil
		}
		return "", err
	}
	removeStale(dir, name)
	return dst, nil
}

// cacheDir returns the private per-user directory for the unpacked binary.
// There is deliberately no fallback to the shared temp directory.
func cacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no user cache directory: %w", err)
	}
	dir := filepath.Join(base, "oncedrop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := checkPrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func fileHasSum(p string, want []byte) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return bytes.Equal(h.Sum(nil), want), nil
}

// removeStale deletes binaries left by other oncedrop versions. Failures
// (e.g. a copy still running on Windows) are ignored.
func removeStale(dir, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, "cloudflared-") && n != keep {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
}
