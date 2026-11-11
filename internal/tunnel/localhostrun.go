package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const lhrHost = "localhost.run:22"

// lhrHostKeys pins localhost.run's host keys (checked 2026-09).
// Even if it rotates, confidentiality does not depend on it: the tunnel only
// ever carries ciphertext, and the key lives in the URL fragment.
var lhrHostKeys = []string{
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILVqOuSMnyeGDVO1lG6EaG5In/dXABCchhmHKkuRU2s9",
	"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3lJnhW1oCXuAYV9IBdcJA+Vx7AHL5S/ZQvV2fhceOAPgO2kNQZla6xvUwoE4iw8lYu3zoE1KtieCU9yInWOVI6W/wFaT/ETH1tn55T2FVsK/zaxPiHZVJGLPPdEEid0vS2p1JDfc9onZ0pNSHLl1QusIOeMUyZ2bUMMLLgw46KOT9S3s/LmxgoJ3PocVUn5rVXz/Dng7Y8jYNe4IFrZOAUsi7hNBa+OYja6ceefpDvNDEJ1BdhbYfGolBdNA7f+FNl0kfaWru4Cblr843wBe2ckO/sNqgeAMXO/qH+SSgQxUXF2AgAw+TGp3yCIyYoOPvOgvcPsQziJLmDbUuQpnH",
}

var lhrURL = regexp.MustCompile(`https://[a-z0-9-]+\.lhr\.life`)

// AllowUnknownHostKey disables host-key pinning for localhost.run.
var AllowUnknownHostKey = false

type localhostRun struct {
	client *ssh.Client
	url    string
	done   chan struct{}
	err    error
	once   sync.Once
}

// startLocalhostRun implements `ssh -R 80:127.0.0.1:port nokey@localhost.run`
// in pure Go. The service accepts anonymous users and prints the public
// hostname on the session's stdout.
func startLocalhostRun(ctx context.Context, port int) (Tunnel, error) {
	pinned := make([][]byte, 0, len(lhrHostKeys))
	for _, k := range lhrHostKeys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return nil, err
		}
		pinned = append(pinned, pk.Marshal())
	}
	cfg := &ssh.ClientConfig{
		User:              "nokey",
		Auth:              []ssh.AuthMethod{}, // "none" auth is always attempted first
		Timeout:           20 * time.Second,
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if AllowUnknownHostKey {
				return nil
			}
			got := key.Marshal()
			for _, p := range pinned {
				if string(got) == string(p) {
					return nil
				}
			}
			return fmt.Errorf("localhost.run host key mismatch (%s); rerun with -insecure-hostkey if it was rotated", ssh.FingerprintSHA256(key))
		},
	}

	dialer := net.Dialer{Timeout: cfg.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", lhrHost)
	if err != nil {
		return nil, fmt.Errorf("localhost.run: %w", err)
	}
	c, chans, reqs, err := ssh.NewClientConn(rawConn, lhrHost, cfg)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("localhost.run ssh: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	t := &localhostRun{client: client, done: make(chan struct{})}

	// Order matters with this server: it only answers the tcpip-forward
	// request once a session exists, and it never answers the "shell"
	// request at all. So: open session, fire shell without waiting for a
	// reply, then request the forward.
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		client.Close()
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		client.Close()
		return nil, err
	}
	go io.Copy(io.Discard, stderr)
	if _, err := sess.SendRequest("shell", false, nil); err != nil {
		client.Close()
		return nil, err
	}

	// Remote port forward: whatever hits our public hostname arrives here.
	ln, err := client.Listen("tcp", "localhost:80")
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("localhost.run: remote forward refused: %w", err)
	}
	go t.serve(ln, port)

	urlCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		found := false
		for sc.Scan() {
			if !found {
				if m := lhrURL.FindString(sc.Text()); m != "" {
					found = true
					urlCh <- m
				}
			}
		}
	}()
	go func() {
		t.finish(client.Wait())
	}()
	go t.keepalive()

	select {
	case u := <-urlCh:
		t.url = u
		return t, nil
	case <-t.done:
		return nil, fmt.Errorf("localhost.run closed the connection: %v", t.err)
	case <-time.After(30 * time.Second):
		client.Close()
		return nil, fmt.Errorf("localhost.run: timed out waiting for tunnel URL")
	case <-ctx.Done():
		client.Close()
		return nil, ctx.Err()
	}
}

func (t *localhostRun) serve(ln net.Listener, port int) {
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for {
		remote, err := ln.Accept()
		if err != nil {
			t.finish(err)
			return
		}
		go func() {
			defer remote.Close()
			local, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				return
			}
			defer local.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(local, remote); local.(*net.TCPConn).CloseWrite() }()
			go func() { defer wg.Done(); io.Copy(remote, local) }()
			wg.Wait()
		}()
	}
}

func (t *localhostRun) keepalive() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			if _, _, err := t.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				t.finish(err)
				t.client.Close()
				return
			}
		}
	}
}

func (t *localhostRun) finish(err error) {
	t.once.Do(func() {
		if err == nil {
			err = fmt.Errorf("localhost.run connection closed")
		}
		t.err = err
		close(t.done)
	})
}

func (t *localhostRun) URL() string           { return t.url }
func (t *localhostRun) Done() <-chan struct{} { return t.done }
func (t *localhostRun) Err() error            { return t.err }
func (t *localhostRun) Provider() string      { return ProviderLocalhostRun }
func (t *localhostRun) Close() error          { return t.client.Close() }
