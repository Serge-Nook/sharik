//go:build windows

package scanner

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// hideConsole keeps child processes from flashing a console window.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
