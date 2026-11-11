// Command release builds oncedrop with the matching official cloudflared
// binary embedded, for the host or for every supported platform.
//
//	go run ./tools/release              # host build -> ./oncedrop[.exe]
//	go run ./tools/release -all         # every platform -> dist/
//	go run ./tools/release -os windows -arch amd64
//
// Downloads are cached in .cache/cloudflared/<version>/ and must match
// tools/release/cloudflared.sums. Platforms without an upstream cloudflared
// build get a oncedrop without it (it then uses localhost.run).
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const cloudflaredVersion = "2026.9.1"

var platforms = []string{
	"linux/amd64", "linux/arm64", "linux/arm", "linux/386",
	"windows/amd64", "windows/386", "windows/arm64",
	"darwin/amd64", "darwin/arm64",
}

const stageDir = "internal/cfbin/bin"

func main() {
	all := flag.Bool("all", false, "build every platform into dist/")
	goos := flag.String("os", runtime.GOOS, "target GOOS")
	goarch := flag.String("arch", runtime.GOARCH, "target GOARCH")
	noCF := flag.Bool("no-cloudflared", false, "do not embed cloudflared")
	ver := flag.String("version", "dev", "version string embedded in the binary")
	flag.Parse()
	log.SetFlags(0)

	root, err := repoRoot()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat("web/dist/admin.html"); err != nil {
		log.Fatal("frontend not built: run `make` or `npm ci && npm run build` in web/ first")
	}
	defer unstage()

	if !*all {
		out := "oncedrop" + exe(*goos)
		if err := build(*goos, *goarch, out, *ver, !*noCF); err != nil {
			unstage()
			log.Fatal(err)
		}
		return
	}

	if err := os.MkdirAll("dist", 0o755); err != nil {
		log.Fatal(err)
	}
	var sums strings.Builder
	for _, p := range platforms {
		goos, goarch, _ := strings.Cut(p, "/")
		out := filepath.Join("dist", "oncedrop-"+goos+"-"+goarch+exe(goos))
		if err := build(goos, goarch, out, *ver, !*noCF); err != nil {
			unstage()
			log.Fatalf("%s: %v", p, err)
		}
		sum, err := fileSum(out)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(&sums, "%s  %s\n", sum, filepath.Base(out))
	}
	if err := os.WriteFile(filepath.Join("dist", "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		log.Fatal(err)
	}
}

func build(goos, goarch, out, version string, embed bool) error {
	unstage()
	if embed {
		if err := stage(goos, goarch); err != nil {
			return err
		}
	}
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -X main.version="+version, "-o", out, ".")
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	if goarch == "arm" {
		cmd.Env = append(cmd.Env, "GOARM=7")
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	st, err := os.Stat(out)
	if err != nil {
		return err
	}
	log.Printf("built %-40s %5.1f MB", out, float64(st.Size())/(1<<20))
	return nil
}

func exe(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func assetName(goos, goarch string) string {
	switch goos + "/" + goarch {
	case "linux/amd64", "linux/arm64", "linux/arm", "linux/386":
		return "cloudflared-" + goos + "-" + goarch
	case "windows/amd64", "windows/386":
		return "cloudflared-" + goos + "-" + goarch + ".exe"
	case "darwin/amd64", "darwin/arm64":
		return "cloudflared-" + goos + "-" + goarch + ".tgz"
	}
	return ""
}

// stage puts the gzipped cloudflared for goos/goarch where cfbin embeds it.
func stage(goos, goarch string) error {
	asset := assetName(goos, goarch)
	if asset == "" {
		log.Printf("no cloudflared build for %s/%s, not embedding", goos, goarch)
		return nil
	}
	path, err := fetch(asset)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var bin io.Reader = f
	if strings.HasSuffix(asset, ".tgz") {
		if bin, err = fromTgz(f, "cloudflared"); err != nil {
			return fmt.Errorf("%s: %w", asset, err)
		}
	}

	gzf, err := os.Create(filepath.Join(stageDir, "cloudflared.gz"))
	if err != nil {
		return err
	}
	defer gzf.Close()
	zw, _ := gzip.NewWriterLevel(gzf, gzip.BestCompression)
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(zw, h), bin); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageDir, "cloudflared.sha256"), []byte(hex.EncodeToString(h.Sum(nil))+"\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stageDir, "cloudflared.version"), []byte(cloudflaredVersion+"\n"), 0o644)
}

func unstage() {
	matches, _ := filepath.Glob(filepath.Join(stageDir, "cloudflared*"))
	for _, m := range matches {
		os.Remove(m)
	}
}

func fromTgz(r io.Reader, name string) (io.Reader, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("%s not found in archive: %w", name, err)
		}
		if filepath.Base(h.Name) == name && h.Typeflag == tar.TypeReg {
			return tr, nil
		}
	}
}

// fetch returns the cached, checksum-verified release asset.
func fetch(asset string) (string, error) {
	want, err := pinnedSum(asset)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(".cache", "cloudflared", cloudflaredVersion)
	path := filepath.Join(dir, asset)
	if got, err := fileSum(path); err == nil && got == want {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	url := "https://github.com/cloudflare/cloudflared/releases/download/" + cloudflaredVersion + "/" + asset
	log.Printf("downloading %s", url)
	res, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", url, res.StatusCode)
	}
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), res.Body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		return "", fmt.Errorf("%s: checksum mismatch: got %s, want %s", asset, got, want)
	}
	return path, os.Rename(tmp, path)
}

func pinnedSum(asset string) (string, error) {
	f, err := os.Open(filepath.Join("tools", "release", "cloudflared.sums"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	versionOK := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "# version "+cloudflaredVersion {
			versionOK = true
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset && !strings.HasPrefix(line, "#") {
			if !versionOK {
				break
			}
			return fields[0], nil
		}
	}
	if !versionOK {
		return "", fmt.Errorf("cloudflared.sums is not for version %s", cloudflaredVersion)
	}
	return "", fmt.Errorf("no pinned checksum for %s", asset)
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil &&
			slices.Contains(strings.Split(string(b), "\n"), "module github.com/uetam3/oncedrop") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run this inside the oncedrop repository")
		}
		dir = parent
	}
}
