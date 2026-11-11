package tunnel

import (
	"os/exec"
	"syscall"
)

// setChildAttrs makes the kernel kill cloudflared if oncedrop dies
// without cleaning up (kill -9, crash).
func setChildAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func bindChild(*exec.Cmd) func() { return func() {} }
