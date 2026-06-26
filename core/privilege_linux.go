//go:build linux

package core

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// IsElevated 检查是否为root权限
func IsElevated() bool {
	return os.Getuid() == 0
}

// GetUsername 获取当前用户名
func GetUsername() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USER")
	}
	return u.Username
}

// EnablePrivilege Linux上无需Windows式提权，若已是root则直接操作
func EnablePrivilege(name string) error {
	if IsElevated() {
		return nil
	}
	// 尝试sudo提权
	return fmt.Errorf("not root, privilege escalation requires sudo")
}

// TryElevate Linux上检查是否有sudo权限
func TryElevate() bool {
	_, err := ExecCmd("sudo", "-n", "true")
	return err == nil
}

// PrivilegeInfo 权限信息
type PrivilegeInfo struct {
	Elevated  bool   `json:"elevated"`
	Username  string `json:"username"`
	DebugPriv bool   `json:"debug_priv"` // Linux上表示sudo权限
}

// GetPrivilegeInfo 收集权限信息
func GetPrivilegeInfo() *PrivilegeInfo {
	uid := os.Getuid()
	info := &PrivilegeInfo{
		Elevated:  uid == 0,
		Username:  GetUsername(),
		DebugPriv: TryElevate(),
	}
	return info
}

// FormatPrivilegeInfo 格式化权限信息
func FormatPrivilegeInfo(info *PrivilegeInfo) string {
	uid := os.Getuid()
	gid := os.Getgid()
	return fmt.Sprintf("Root: %v | User: %s (uid=%d gid=%d) | Sudo: %v",
		info.Elevated, info.Username, uid, gid, info.DebugPriv)
}

// GetUID 获取UID
func GetUID() int {
	return os.Getuid()
}

// GetGID 获取GID
func GetGID() int {
	return os.Getgid()
}

// GetGroups 获取用户组
func GetGroups() []int {
	groups, _ := os.Getgroups()
	return groups
}

// CanWritePath 检查当前用户对路径的写权限
func CanWritePath(path string) bool {
	// 简化: 尝试打开文件写
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// FormatGroups 格式化组信息
func FormatGroups(groups []int) string {
	return strconv.Itoa(os.Getgid())
}
