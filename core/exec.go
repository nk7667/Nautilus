//go:build windows

package core

import (
	"bytes"
	"os/exec"
	"syscall"
)

// ExecCmd 执行命令并返回输出，隐藏窗口
func ExecCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

// ExecCmdWithShell 通过cmd.exe /c 执行命令
func ExecCmdWithShell(command string) (string, error) {
	return ExecCmd("cmd.exe", "/c", command)
}

// ExecCmdWithPowerShell 通过powershell执行命令
func ExecCmdWithPowerShell(command string) (string, error) {
	return ExecCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
}
