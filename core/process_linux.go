//go:build linux

package core

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ProcessList 获取进程列表 (Linux: ps命令)
func ProcessList() ([]string, error) {
	out, err := ExecCmd("ps", "aux")
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

// ProcessKillByName 按名称杀死进程 (Linux: killall)
func ProcessKillByName(name string) error {
	_, err := ExecCmd("killall", name)
	return err
}

// ProcessCreate 创建新进程
func ProcessCreate(path string, args ...string) (int, error) {
	cmd := exec.Command(path, args...)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

// GetPID 获取当前进程PID
func GetPID() int {
	return os.Getpid()
}

// GetPPID 获取父进程PID (Linux: /proc/self/stat)
func GetPPID() (int, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	// /proc/self/stat格式: pid (comm) state ppid ...
	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return 0, fmt.Errorf("invalid /proc/self/stat")
	}
	ppid := 0
	fmt.Sscanf(fields[3], "%d", &ppid)
	return ppid, nil
}

// IsProcessRunning 检查进程是否存在 (Linux: pgrep)
func IsProcessRunning(name string) bool {
	out, _ := ExecCmd("pgrep", "-x", name)
	lines := splitLines(out)
	return len(lines) > 0
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}
