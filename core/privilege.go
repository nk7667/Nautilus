//go:build windows

package core

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modadvapi32         = syscall.NewLazyDLL("advapi32.dll")
	procGetUserNameW    = modadvapi32.NewProc("GetUserNameW")
	procLookupPrivilege = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPriv = modadvapi32.NewProc("AdjustTokenPrivileges")
)

// IsElevated 检查当前进程是否具有管理员权限
func IsElevated() bool {
	var token syscall.Token
	currentProc, _ := syscall.GetCurrentProcess()
	err := syscall.OpenProcessToken(currentProc, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	var returnedLen uint32
	err = syscall.GetTokenInformation(token, syscall.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	return elevation != 0
}

// GetUsername 获取当前用户名 (Win32 API)
func GetUsername() string {
	var size uint32 = 256
	buf := make([]uint16, size)
	procGetUserNameW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	return syscall.UTF16ToString(buf)
}

// LUID 对应Windows LUID结构
type LUID struct {
	LowPart  uint32
	HighPart uint32
}

// LUIDAndAttributes 对应Windows TOKEN_PRIVILEGES结构
type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

// TokenPrivileges 对应Windows TOKEN_PRIVILEGES
type TokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]LUIDAndAttributes
}

// EnablePrivilege 尝试启用指定权限
func EnablePrivilege(name string) error {
	var token syscall.Token
	currentProc, _ := syscall.GetCurrentProcess()
	if err := syscall.OpenProcessToken(currentProc, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid LUID
	namePtr, _ := syscall.UTF16PtrFromString(name)
	ret, _, err := procLookupPrivilege.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return err
	}

	priv := TokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]LUIDAndAttributes{
			{Luid: luid, Attributes: 0x00000002}, // SE_PRIVILEGE_ENABLED
		},
	}

	ret, _, err = procAdjustTokenPriv.Call(
		uintptr(token),
		0, // FALSE
		uintptr(unsafe.Pointer(&priv)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return err
	}
	return nil
}

// TryElevate 尝试提权 (SeDebugPrivilege)
func TryElevate() bool {
	err := EnablePrivilege("SeDebugPrivilege")
	return err == nil
}

// PrivilegeInfo 权限信息
type PrivilegeInfo struct {
	Elevated  bool   `json:"elevated"`
	Username  string `json:"username"`
	DebugPriv bool   `json:"debug_priv"`
}

// GetPrivilegeInfo 收集权限信息
func GetPrivilegeInfo() *PrivilegeInfo {
	info := &PrivilegeInfo{
		Elevated:  IsElevated(),
		Username:  GetUsername(),
		DebugPriv: TryElevate(),
	}
	return info
}

// FormatPrivilegeInfo 格式化权限信息
func FormatPrivilegeInfo(info *PrivilegeInfo) string {
	return fmt.Sprintf("Elevated: %v | User: %s | SeDebugPriv: %v", info.Elevated, info.Username, info.DebugPriv)
}
