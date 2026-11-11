//go:build !linux && !windows

package tunnel

import "os/exec"

func setChildAttrs(*exec.Cmd) {}

func bindChild(*exec.Cmd) func() { return func() {} }
