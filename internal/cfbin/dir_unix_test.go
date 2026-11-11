//go:build !windows

package cfbin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPrivateDir(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "good")
	if err := os.Mkdir(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDir(good); err != nil {
		t.Fatalf("0700 dir rejected: %v", err)
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o770); err != nil {
		t.Fatal(err)
	}
	if checkPrivateDir(loose) == nil {
		t.Fatal("0770 dir accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if checkPrivateDir(link) == nil {
		t.Fatal("symlink accepted")
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if checkPrivateDir(file) == nil {
		t.Fatal("regular file accepted")
	}
}
