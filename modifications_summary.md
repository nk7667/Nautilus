# Fish C2 免杀改造总结

## 检测规则分析 (Phase 2-3)

| # | 检测规则 | 命中模式 | 绕过策略 |
|---|---------|---------|---------|
| R1 | Mandiant capa: "compiled with Go" | `go.buildid`, `runtime.main`, `Go build ID:` | `-buildid=` ldflag + 二进制后处理清零 |
| R2 | YARA: Go shellcode loader | `NtAllocateVirtualMemory`/`NtProtectVirtualMemory` 字符串 | XOR加密API名，运行时解密 |
| R3 | YARA: DLL名字符串 | `"ntdll.dll"`, `"kernel32.dll"`, `"user32.dll"` | XOR加密DLL名，运行时解密 |
| R4 | 启发式: RW→RX权限翻转 | VirtualAlloc(RW)→VirtualProtect(RX)行为链 | 已使用Nt* API + Permission Flipping |
| R5 | 启发式: 直接跳转执行 | `syscall.SyscallN(baseAddr)` 直接跳转到动态内存 | EnumWindows回调执行 (T010) |
| R6 | YARA: 敏感关键词 | `shellcode`, `AmsiScanBuffer`, `B8 57 00 07 80 C3` | NTDLL Unhook替代AMSI patch + 重命名 |
| R7 | Sigma: Go进程+反调试 | `IsDebuggerPresent` + `GlobalMemoryStatusEx` | API名XOR加密 |

## 代码修改 (Phase 4)

### 新增文件

| 文件 | 说明 |
|------|------|
| `evasion/apiresolve_windows.go` | API名XOR加密解析模块，替代所有硬编码DLL/API字符串 |

### 修改文件

| 文件 | 修改内容 |
|------|---------|
| `core/shellcode_windows.go` | 1. 使用`evasion.CallNtAVM/CallNtPVM`替代硬编码API名<br>2. 使用`evasion.CallEnumWindows`回调执行替代`syscall.SyscallN`<br>3. 重命名`XorEncShellcode`→`XorEncPayload` |
| `evasion/unhook_windows.go` | 1. 使用`xorDec(encNtDll, xk)`替代`"ntdll.dll"`<br>2. 使用`CallNtPVM/CallRtlCopy`替代硬编码API<br>3. 使用`k32Proc(encCFW/encRF/encCH/encGFS)`替代`"kernel32.dll"` API<br>4. XOR加密`C:\Windows\System32\ntdll.dll`路径 |
| `evasion/sandbox.go` | 使用`k32Proc(encGMSE/encGTC/encIDP)`替代硬编码API名 |
| `shellcode_handler_windows.go` | 重命名`handleShellcode`→`handlePayload`，清理敏感字符串 |
| `shellcode_handler_linux.go` | 同步重命名 |
| `c2/encode/packet.go` | `TaskShellcode`→`TaskPayload` |
| `main.go` | 同步引用更新 |
| `stager/main_windows.go` | 全面改造：XOR加密API名 + EnumWindows回调 + 去除VirtualAlloc/VirtualProtect |
| `build.ps1` | 1. 添加`-buildid=` ldflag<br>2. 添加Go build ID字符串后处理清零<br>3. 添加PE patch + overlay |

## 验证结果 (Phase 5)

| 检测模式 | 结果 |
|---------|------|
| `NtAllocateVirtualMemory` | CLEAN |
| `NtProtectVirtualMemory` | CLEAN |
| `VirtualProtect` | CLEAN |
| `AmsiScanBuffer` | CLEAN |
| `EtwEventWrite` | CLEAN |
| `Go build ID:` | CLEAN |
| `go.buildid` | CLEAN |
| `shellcode` | CLEAN (源码) |
| `VirtualAlloc` | FOUND (Go runtime内部引用) |
| `kernel32.dll` | FOUND (Go runtime内部引用) |
| `ntdll.dll` | FOUND (Go runtime内部引用) |

> 注: `VirtualAlloc`/`kernel32.dll`/`ntdll.dll` 来自Go标准库runtime包，无法从源码层面消除。
> garble `-literals` 混淆可以部分缓解，但Go运行时仍需加载这些DLL。
> 进一步绕过需要使用garble混淆编译 + 自定义Go runtime补丁。

## 免杀技术栈

```
编译期:
  -ldflags "-s -w -buildid= -H windowsgui"  → 去符号/去build ID/隐藏窗口
  garble -tiny -literals -seed=random        → 混淆符号名和字符串字面量

运行时:
  NTDLL Unhooking (T006)                     → 移除EDR Hook
  API Name XOR Encryption                    → 消除静态DLL/API字符串
  Permission Flipping (T005)                 → RW→RX避免RWX
  Callback Execution (T010)                  → EnumWindows替代直接跳转
  Anti-Sandbox + Anti-Debug                  → 反分析

后处理:
  PE Timestamp Patch                         → 修改编译时间戳
  Go Build ID Zeroing                        → 清零Go标识字符串
  Random Overlay Data                        → 改变文件哈希
```
