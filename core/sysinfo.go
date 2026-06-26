package core

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
)

// SysInfo 系统信息结构
type SysInfo struct {
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Username string   `json:"username"`
	PID      int      `json:"pid"`
	PPID     int      `json:"ppid"`
	TempDir  string   `json:"temp_dir"`
	HomeDir  string   `json:"home_dir"`
	IPs      []string `json:"ips"`
}

// GetSysInfo 收集系统信息
func GetSysInfo() *SysInfo {
	info := &SysInfo{
		Hostname: getHostname(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
		TempDir:  os.TempDir(),
	}

	// 用户名
	u, err := user.Current()
	if err == nil {
		info.Username = u.Username
		info.HomeDir = u.HomeDir
	}

	// 父进程PID
	ppid, err := GetPPID()
	if err == nil {
		info.PPID = ppid
	}

	// IP地址 (平台特定实现)
	info.IPs = getIPs()

	return info
}

func getHostname() string {
	h, _ := os.Hostname()
	return h
}

// FormatSysInfo 格式化系统信息为字符串
func FormatSysInfo(info *SysInfo) string {
	return fmt.Sprintf(
		"Host: %s | OS: %s/%s | User: %s | PID: %d | PPID: %d | Temp: %s | IPs: %v",
		info.Hostname, info.OS, info.Arch, info.Username,
		info.PID, info.PPID, info.TempDir, info.IPs,
	)
}
