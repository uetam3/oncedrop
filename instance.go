package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/uetam3/oncedrop/internal/server"
)

func defaultSecretFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "oncedrop", "admin-key")
}

// loadSecret reads the panel key, creating it on first run. Keeping it on
// disk lets a bookmarked panel survive restarts.
func loadSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		k := strings.TrimSpace(string(b))
		if len(k) < 32 {
			return "", fmt.Errorf("%s: key too short, delete the file to regenerate it", path)
		}
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	k := base64.RawURLEncoding.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return loadSecret(path) // another instance was faster
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(k + "\n"); err != nil {
		return "", err
	}
	return k, nil
}

// requireLoopback refuses to expose the panel beyond this machine.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s is not a loopback address", addr)
	}
	return nil
}

var localClient = &http.Client{Timeout: 3 * time.Minute}

// checkInstance asks whatever listens on addr whether it is oncedrop. running
// is false when it is not (or nothing answers). When it claims to be oncedrop
// but cannot prove it knows secret, err is set: that is another user's copy,
// a copy with a different -secret-file, or an impostor, and it must get
// neither the key nor any file.
func checkInstance(addr, secret string) (running bool, err error) {
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return false, err
	}
	nonce := hex.EncodeToString(nb)
	c := http.Client{Timeout: 2 * time.Second}
	res, err := c.Get("http://" + addr + "/healthz?nonce=" + nonce)
	if err != nil {
		return false, nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 256))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if lines[0] != server.AppID {
		return false, nil
	}
	want := server.InstanceProof(secret, nonce)
	if len(lines) != 2 || !hmac.Equal([]byte(lines[1]), []byte(want)) {
		return true, fmt.Errorf("the oncedrop on %s does not know this panel key (another user's copy, a different -secret-file, or not oncedrop at all); refusing to hand anything over", addr)
	}
	return true, nil
}

// handOver passes files to the instance already listening on addr, or just
// opens its panel when there are none.
func handOver(ctx context.Context, addr, secret string, files []string, ttl time.Duration, printQR, open bool) error {
	if _, err := checkInstance(addr, secret); err != nil {
		return err
	}
	cookie := server.CookieName(addr) + "=" + secret
	if len(files) == 0 {
		fmt.Printf("oncedrop is already running: http://%s/?k=%s\n", addr, secret)
		if open {
			u, err := loginLink(ctx, addr, cookie)
			if err != nil {
				return err
			}
			openBrowser(u)
		}
		return nil
	}
	fmt.Printf("oncedrop is already running at %s; handing files over (the tunnel may take a few seconds)\n", addr)
	var failed int
	for _, path := range files {
		if err := uploadTo(ctx, addr, cookie, path, ttl, printQR); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d files failed", failed, len(files))
	}
	return nil
}

// loginLink asks the running instance for a one-time panel login link.
func loginLink(ctx context.Context, addr, cookie string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/api/login-link", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Requested-With", server.AppID)
	req.Header.Set("Cookie", cookie)
	res, err := localClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out); err != nil || res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login link: HTTP %d", res.StatusCode)
	}
	return out.URL, nil
}

func uploadTo(ctx context.Context, addr, cookie, path string, ttl time.Duration, printQR bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return err
	}
	fw.Write(data)
	mw.WriteField("ttlSec", strconv.Itoa(int(ttl.Seconds())))
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/api/share", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Requested-With", server.AppID)
	req.Header.Set("Cookie", cookie)
	res, err := localClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var out struct {
		URL   string `json:"url"`
		Name  string `json:"name"`
		Size  int    `json:"size"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if res.StatusCode != http.StatusCreated {
		if res.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("the running instance uses a different -secret-file")
		}
		return fmt.Errorf("%s", out.Error)
	}
	printShare(out.Name, out.Size, ttl, out.URL, printQR)
	return nil
}
