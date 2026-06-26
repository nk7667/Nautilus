//go:build linux

package evasion

import (
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// AntiSandbox 基础反沙箱检测 (Linux版)
func AntiSandbox() bool {
	// 检查CPU核心数
	if runtime.NumCPU() < 2 {
		return true
	}

	// 检查内存大小 (Linux: /proc/meminfo)
	memKB := readMemInfo()
	if memKB < 2*1024*1024 { // < 2GB
		return true
	}

	// 检查系统运行时间 (Linux: /proc/uptime)
	uptime := readUptime()
	if uptime < 10*time.Minute {
		return true
	}

	// 检查常见沙箱用户名
	username := os.Getenv("USER")
	if username == "user" || username == "sandbox" {
		return true
	}

	// 检查是否在容器中 (Docker/LXC)
	if isInContainer() {
		return true
	}

	return false
}

// AntiDebug 反调试检测 (Linux)
func AntiDebug() bool {
	// 检查TracerPid (/proc/self/status)
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			if pid != "0" {
				return true // 被调试
			}
		}
	}
	return false
}

// readMemInfo 从/proc/meminfo读取总内存(KB)
func readMemInfo() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb uint64
				for i := 0; i < len(fields[1]); i++ {
					kb = kb*10 + uint64(fields[1][i]-'0')
				}
				return kb
			}
		}
	}
	return 0
}

// readUptime 从/proc/uptime读取系统运行时间
func readUptime() time.Duration {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	var seconds float64
	for i, c := range fields[0] {
		if c == '.' {
			// 简化解析
			continue
		}
		seconds = seconds*10 + float64(c-'0')
		if i > 0 && fields[0][i-1] == '.' {
			seconds += float64(c-'0') * 0.1
		}
	}
	return time.Duration(seconds) * time.Second
}

// isInContainer 检查是否在容器中运行
func isInContainer() bool {
	// 检查 /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// 检查 /proc/1/cgroup
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	if strings.Contains(string(data), "docker") ||
		strings.Contains(string(data), "lxc") {
		return true
	}
	return false
}

// CheckPhysicalMem Linux版: 返回总物理内存字节
func CheckPhysicalMem() uint64 {
	return readMemInfo() * 1024 // KB -> Bytes
}

// NumCPU 获取CPU核心数
func NumCPU() int {
	return runtime.NumCPU()
}

// GetUptime Linux版: 获取系统运行时间
func GetUptime() time.Duration {
	return readUptime()
}

// GetUsername Linux版: 获取当前用户名
func GetUsername() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USER")
	}
	return u.Username
}
