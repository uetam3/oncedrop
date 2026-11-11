package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var cfURL = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)

type cloudflared struct {
	cmd     *exec.Cmd
	cleanup func()
	url     string
	done    chan struct{}
	err     error
	once    sync.Once

	mu   sync.Mutex
	tail []string // last log lines, for error messages
}

// startCloudflared runs a Cloudflare "quick tunnel": no account, no login,
// random *.trycloudflare.com hostname with TLS terminated by Cloudflare.
func startCloudflared(ctx context.Context, bin string, port int) (Tunnel, error) {
	// A quick tunnel refuses to start when the user's ~/.cloudflared config
	// names a tunnel, so point it at an empty config of our own.
	cfgDir, err := os.MkdirTemp("", "oncedrop-cf-")
	if err != nil {
		return nil, err
	}
	cfg := filepath.Join(cfgDir, "config.yml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		os.RemoveAll(cfgDir)
		return nil, err
	}

	cmd := exec.Command(bin, "tunnel",
		"--config", cfg,
		"--no-autoupdate",
		"--metrics", "127.0.0.1:0",
		"--url", fmt.Sprintf("http://127.0.0.1:%d", port))
	cmd.Env = append(os.Environ(), "TUNNEL_ORIGIN_CERT=", "NO_AUTOUPDATE=true")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.RemoveAll(cfgDir)
		return nil, err
	}
	cmd.Stdout = io.Discard
	setChildAttrs(cmd)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(cfgDir)
		return nil, err
	}
	release := bindChild(cmd)
	t := &cloudflared{
		cmd:  cmd,
		done: make(chan struct{}),
		cleanup: func() {
			release()
			os.RemoveAll(cfgDir)
		},
	}

	urlCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		found := false
		for sc.Scan() {
			line := sc.Text()
			t.remember(line)
			if !found {
				if m := cfURL.FindString(line); m != "" {
					found = true
					urlCh <- m
				}
			}
		}
		t.finish(cmd.Wait())
	}()

	select {
	case u := <-urlCh:
		t.url = u
		return t, nil
	case <-t.done:
		return nil, fmt.Errorf("cloudflared exited before publishing a URL: %v%s", t.err, t.lastLog())
	case <-time.After(45 * time.Second):
		t.Close()
		return nil, fmt.Errorf("cloudflared: timed out waiting for tunnel URL%s", t.lastLog())
	case <-ctx.Done():
		t.Close()
		return nil, ctx.Err()
	}
}

func (t *cloudflared) remember(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if strings.Contains(line, " ERR ") || strings.Contains(line, "error") {
		t.tail = append(t.tail, line)
		if len(t.tail) > 3 {
			t.tail = t.tail[1:]
		}
	}
}

func (t *cloudflared) lastLog() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.tail) == 0 {
		return ""
	}
	return ": " + strings.Join(t.tail, " | ")
}

func (t *cloudflared) finish(err error) {
	t.once.Do(func() {
		if err == nil {
			err = fmt.Errorf("cloudflared exited")
		}
		t.err = err
		t.cleanup()
		close(t.done)
	})
}

func (t *cloudflared) URL() string           { return t.url }
func (t *cloudflared) Done() <-chan struct{} { return t.done }
func (t *cloudflared) Err() error            { return t.err }
func (t *cloudflared) Provider() string      { return ProviderCloudflared }
func (t *cloudflared) Close() error {
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	return nil
}
