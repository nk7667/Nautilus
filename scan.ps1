# Fish AV Scanner - 一键多引擎杀软检测
# 使用VirusTotal API v3 扫描编译产物
# 用法: .\scan.ps1 -ApiKey "你的VT API Key" -File "fish.exe"

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [string]$File = "fish.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) {
    Write-Host "[!] File not found: $File" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item $File).Length
Write-Host "[+] File: $File ($fileSize bytes)" -ForegroundColor Cyan

# Step 1: 计算文件哈希
Write-Host "[+] Calculating file hash..." -ForegroundColor Yellow
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = [System.IO.File]::ReadAllBytes($File)
$hash = [System.BitConverter]::ToString($sha256.ComputeHash($hashBytes)).Replace("-","").ToLower()
Write-Host "[+] SHA256: $hash" -ForegroundColor Green

# Step 2: 查询VT是否已有报告
Write-Host "[+] Checking VirusTotal for existing report..." -ForegroundColor Yellow
$headers = @{ "x-apikey" = $ApiKey }

try {
    $reportResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers $headers -Method Get -ErrorAction Stop
    $stats = $reportResp.data.attributes.last_analysis_stats
    Write-Host ""
    Write-Host "=== Existing Report Found ===" -ForegroundColor Green
    Write-Host "  Malicious:  $($stats.malicious)" -ForegroundColor Red
    Write-Host "  Suspicious: $($stats.suspicious)" -ForegroundColor Yellow
    Write-Host "  Undetected: $($stats.undetected)" -ForegroundColor Green
    Write-Host "  Harmless:   $($stats.harmless)" -ForegroundColor Green
    Write-Host ""
    
    # 显示检测到的引擎
    $results = $reportResp.data.attributes.last_analysis_results
    $detected = $results.PSObject.Properties | Where-Object { $_.Value.category -eq "malicious" -or $_.Value.category -eq "suspicious" }
    if ($detected) {
        Write-Host "=== Detected By ===" -ForegroundColor Red
        foreach ($d in $detected) {
            Write-Host "  $($d.Name): $($d.Value.result)" -ForegroundColor Red
        }
    }
    
    $clean = $results.PSObject.Properties | Where-Object { $_.Value.category -eq "undetected" }
    Write-Host ""
    Write-Host "=== Clean Engines ($($clean.Count)) ===" -ForegroundColor Green
    $cleanNames = ($clean | ForEach-Object { $_.Name }) -join ", "
    Write-Host "  $cleanNames"
    
    exit 0
} catch {
    # 404 = 没有报告，需要上传
    Write-Host "[+] No existing report, uploading file..." -ForegroundColor Yellow
}

# Step 3: 上传文件 (小于32MB用普通上传)
if ($fileSize -gt 32MB) {
    Write-Host "[!] File too large for direct upload (>32MB)" -ForegroundColor Red
    exit 1
}

$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"

$bodyLines = @(
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $File -Leaf)`"",
    "Content-Type: application/octet-stream",
    "",
    [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($File)),
    "--$boundary--",
    ""
)

$body = $bodyLines -join $LF

try {
    $uploadResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files" -Headers $headers -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
    $analysisId = $uploadResp.data.id
    Write-Host "[+] Upload successful, analysis ID: $analysisId" -ForegroundColor Green
} catch {
    Write-Host "[!] Upload failed: $_" -ForegroundColor Red
    exit 1
}

# Step 4: 等待分析完成
Write-Host "[+] Waiting for analysis to complete..." -ForegroundColor Yellow
$maxWait = 300  # 最多等5分钟
$waited = 0

while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 15
    $waited += 15
    Write-Host "  ... waiting ($waited s)" -ForegroundColor DarkGray
    
    try {
        $analysisResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" -Headers $headers -Method Get
        $status = $analysisResp.data.attributes.status
        
        if ($status -eq "completed") {
            Write-Host "[+] Analysis completed!" -ForegroundColor Green
            break
        }
    } catch {
        # 继续等待
    }
}

if ($waited -ge $maxWait) {
    Write-Host "[!] Timeout waiting for analysis" -ForegroundColor Red
    Write-Host "[+] Check results manually: https://www.virustotal.com/gui/file/$hash" -ForegroundColor Yellow
    exit 1
}

# Step 5: 获取结果
$stats = $analysisResp.data.attributes.stats
Write-Host ""
Write-Host "========== Scan Results ==========" -ForegroundColor Cyan
Write-Host "  Malicious:  $($stats.malicious)" -ForegroundColor Red
Write-Host "  Suspicious: $($stats.suspicious)" -ForegroundColor Yellow
Write-Host "  Undetected: $($stats.undetected)" -ForegroundColor Green
Write-Host "  Harmless:   $($stats.harmless)" -ForegroundColor Green
Write-Host ""

$results = $analysisResp.data.attributes.results
if ($results) {
    $detected = $results.PSObject.Properties | Where-Object { $_.Value.category -eq "malicious" -or $_.Value.category -eq "suspicious" }
    if ($detected) {
        Write-Host "=== Detected By ===" -ForegroundColor Red
        foreach ($d in $detected) {
            Write-Host "  $($d.Name): $($d.Value.result)" -ForegroundColor Red
        }
    }
    
    $clean = $results.PSObject.Properties | Where-Object { $_.Value.category -eq "undetected" }
    Write-Host ""
    Write-Host "=== Clean Engines ($($clean.Count)) ===" -ForegroundColor Green
    $cleanNames = ($clean | ForEach-Object { $_.Name }) -join ", "
    Write-Host "  $cleanNames"
}

Write-Host ""
Write-Host "Full report: https://www.virustotal.com/gui/file/$hash" -ForegroundColor Cyan
