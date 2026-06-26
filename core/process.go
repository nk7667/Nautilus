//go:build windows

package core

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// ProcessList 获取进程列表 (Windows)
func ProcessList() ([]string, error) {
	out, err := ExecCmd("tasklist.exe", "/FO", "CSV", "/NH")
	if err != nil {
		return nil, err
	}
	var procs []string
	lines := splitLines(out)
	for _, line := range lines {
		if line != "" {
			procs = append(procs, line)
		}
	}
	return procs, nil
}

// ProcessKill 杀死指定PID的进程
func ProcessKill(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// ProcessKillByName 按名称杀死进程
func ProcessKillByName(name string) error {
	_, err := ExecCmd("taskkill.exe", "/F", "/IM", name)
	return err
}

// ProcessCreate 创建新进程 (隐藏窗口)
func ProcessCreate(path string, args ...string) (int, error) {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

// GetPID 获取当前进程PID
func GetPID() int {
	return os.Getpid()
}

// GetPPID 获取父进程PID (Windows)
func GetPPID() (int, error) {
	out, err := ExecCmdWithShell(
		fmt.Sprintf("wmic process where ProcessId=%d get ParentProcessId /VALUE", os.Getpid()),
	)
	if err != nil {
		return 0, err
	}
	lines := splitLines(out)
	for _, line := range lines {
		if len(line) > 16 && line[:16] == "ParentProcessId=" {
			pid := 0
			fmt.Sscanf(line[16:], "%d", &pid)
			return pid, nil
		}
	}
	return 0, fmt.Errorf("parent pid not found")
}

// IsProcessRunning 检查进程是否存在
func IsProcessRunning(name string) bool {
	out, _ := ExecCmd("tasklist.exe", "/FI", "IMAGENAME eq "+name, "/NH")
	lines := splitLines(out)
	for _, line := range lines {
		if containsStr(line, name) {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}
