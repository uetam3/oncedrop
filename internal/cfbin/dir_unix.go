//go:build !windows

package cfbin

import (
	"fmt"
	"os"
	"syscall"
)

// checkPrivateDir refuses a cache directory another user could tamper with:
// it must be a real directory (not a symlink), owned by us, with no group or
// world access.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a plain directory; remove it", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible to other users; run: chmod 700 %s", dir, dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s belongs to another user; remove it or fix the owner", dir)
	}
	return nil
}
