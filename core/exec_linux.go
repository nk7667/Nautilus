//go:build linux

package core

import (
	"bytes"
	"os/exec"
)

// ExecCmd 执行命令并返回输出
func ExecCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

// ExecCmdWithShell 通过 /bin/sh -c 执行命令
func ExecCmdWithShell(command string) (string, error) {
	return ExecCmd("/bin/sh", "-c", command)
}

// ExecCmdWithBash 通过 /bin/bash 执行命令 (Linux替代PowerShell)
func ExecCmdWithBash(command string) (string, error) {
	return ExecCmd("/bin/bash", "-c", command)
}

// ExecCmdWithPowerShell Linux上无PowerShell,回退到bash
func ExecCmdWithPowerShell(command string) (string, error) {
	return ExecCmdWithBash(command)
}
