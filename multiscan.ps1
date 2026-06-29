# Multi-platform online malware scanner
# 支持多个在线检测平台同时扫描

param(
    [Parameter(Mandatory=$true)]
    [string]$File,
    [string]$VTApiKey = $env:VT_API_KEY,
    [string]$MetaDefenderApiKey = $env:METADEFENDER_API_KEY
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $File)) {
    Write-Host "[!] File not found: $File"
    exit 1
}

$fileInfo = Get-Item $File
$sha256 = (Get-FileHash -Path $File -Algorithm SHA256).Hash
Write-Host "========== Multi-Platform Scan =========="
Write-Host "File: $($fileInfo.Name) ($($fileInfo.Length) bytes)"
Write-Host "SHA256: $sha256"
Write-Host ""

# ===== 1. VirusTotal =====
Write-Host "===== [1/3] VirusTotal ====="
try {
    $vtHeaders = @{ "x-apikey" = $VTApiKey }
    
    # Check existing report first
    $vtResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha256" -Headers $vtHeaders -ErrorAction SilentlyContinue
    
    if ($vtResp -and $vtResp.data.attributes.last_analysis_stats) {
        $stats = $vtResp.data.attributes.last_analysis_stats
        $total = $stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless
        Write-Host "  Malicious:  $($stats.malicious)"
        Write-Host "  Suspicious: $($stats.suspicious)"
        Write-Host "  Undetected: $($stats.undetected)"
        Write-Host "  Harmless:   $($stats.harmless)"
        Write-Host "  Total:      $total"
        
        if ($stats.malicious -gt 0) {
            Write-Host ""
            Write-Host "  === Detected By ==="
            $results = $vtResp.data.attributes.last_analysis_results
            foreach ($engine in $results.PSObject.Properties) {
                if ($engine.Value.category -eq "malicious" -or $engine.Value.category -eq "suspicious") {
                    Write-Host "  $($engine.Name): $($engine.Value.result)" -ForegroundColor Red
                }
            }
        }
        Write-Host "  Report: https://www.virustotal.com/gui/file/$sha256"
    } else {
        # Upload file
        Write-Host "  No existing report, uploading..."
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileBytes = [System.IO.File]::ReadAllBytes($File)
        $fileName = [System.IO.Path]::GetFileName($File)
        
        $uploadHeaders = @{
            "x-apikey" = $VTApiKey
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }
        
        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
            "Content-Type: application/octet-stream",
            "",
            [System.Text.Encoding]::UTF8.GetString($fileBytes),
            "--$boundary--"
        )
        
        # Use simpler upload approach
        $uploadResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files" -Method POST -Headers @{"x-apikey" = $VTApiKey} -Form @{file = Get-Item -Path $File}
        $analysisId = $uploadResp.data.id
        Write-Host "  Upload OK, waiting for analysis..."
        
        Start-Sleep -Seconds 60
        
        # Get results
        $reportResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" -Headers $vtHeaders
        if ($reportResp.data.attributes.status -eq "completed") {
            $stats = $reportResp.data.attributes.stats
            Write-Host "  Malicious:  $($stats.malicious)"
            Write-Host "  Suspicious: $($stats.suspicious)"
            Write-Host "  Undetected: $($stats.undetected)"
            Write-Host "  Harmless:   $($stats.harmless)"
        } else {
            Write-Host "  Analysis still in progress. Check: https://www.virustotal.com/gui/file/$sha256"
        }
    }
} catch {
    Write-Host "  VirusTotal error: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# ===== 2. MetaDefender (OPSWAT) =====
Write-Host "===== [2/3] MetaDefender Cloud ====="
try {
    # Check by hash first
    $mdResp = Invoke-RestMethod -Uri "https://api.metadefender.com/v4/hash/$sha256" -Headers @{"apikey" = $MetaDefenderApiKey} -ErrorAction SilentlyContinue
    
    if ($mdResp -and $mdResp.scan_results) {
        $sr = $mdResp.scan_results
        Write-Host "  Total engines: $($sr.total_avs)"
        Write-Host "  Detected: $($sr.total_detected_avs)"
        Write-Host "  Scan date: $($sr.start_time)"
        
        if ($sr.total_detected_avs -gt 0) {
            Write-Host ""
            Write-Host "  === Detected By ==="
            foreach ($detail in $sr.scan_details.PSObject.Properties) {
                if ($detail.Value.threat_found) {
                    Write-Host "  $($detail.Name): $($detail.Value.threat_found)" -ForegroundColor Red
                }
            }
        }
        Write-Host "  Report: https://metadefender.opswat.com/results/file/$sha256"
    } else {
        Write-Host "  No existing report. Upload at: https://metadefender.opswat.com/"
        Write-Host "  Hash lookup: https://metadefender.opswat.com/results/file/$sha256"
    }
} catch {
    Write-Host "  MetaDefender: No API key or error. Check manually at https://metadefender.opswat.com/"
}

Write-Host ""

# ===== 3. Hybrid Analysis (CrowdStrike) =====
Write-Host "===== [3/3] Hybrid Analysis (CrowdStrike) ====="
try {
    $haHeaders = @{
        "User-Agent" = "Falcon Sandbox"
        "Accept" = "application/json"
    }
    
    $haResp = Invoke-RestMethod -Uri "https://www.hybrid-analysis.com/api/v2/search/hash/$sha256" -Headers $haHeaders -ErrorAction SilentlyContinue
    
    if ($haResp -and $haResp.count -gt 0) {
        $report = $haResp[0]
        Write-Host "  Verdict: $($report.verdict)" -ForegroundColor $(if ($report.verdict -eq "malicious") { "Red" } elseif ($report.verdict -eq "suspicious") { "Yellow" } else { "Green" })
        Write-Host "  Threat Score: $($report.threat_score)"
        Write-Host "  AV Detect: $($report.av_detect)"
        Write-Host "  Report: https://www.hybrid-analysis.com/sample/$sha256"
    } else {
        Write-Host "  No existing report. Upload at: https://www.hybrid-analysis.com/"
        Write-Host "  Direct upload: https://www.hybrid-analysis.com/submit"
    }
} catch {
    Write-Host "  Hybrid Analysis: Error or no API key. Check manually at https://www.hybrid-analysis.com/"
}

Write-Host ""

# ===== 4. ANY.RUN Interactive Sandbox =====
Write-Host "===== [4/4] ANY.RUN Interactive Sandbox ====="
Write-Host "  File size limit: 500MB"
Write-Host "  Features: Real-time interactive analysis, visual behavior mapping"
Write-Host "  Upload: https://any.run/submit/"
Write-Host "  Hash lookup: https://any.run/report/hash/$sha256"
Write-Host "  Note: Free tier limited to 5 submissions/day"

Write-Host ""

# ===== 5. Joe Sandbox Cloud =====
Write-Host "===== [5/5] Joe Sandbox Cloud ====="
Write-Host "  File size limit: 100MB"
Write-Host "  Features: Dynamic/static analysis, multi-platform (Win/Linux/Android)"
Write-Host "  Upload: https://www.joesecurity.org/submit"
Write-Host "  Hash lookup: https://www.joesecurity.org/analysis/$sha256"

Write-Host ""

# ===== 6. Chinese Threat Intelligence =====
Write-Host "===== [6/6] Chinese Threat Intelligence ====="
Write-Host "  微步在线云沙箱: https://s.threatbook.cn/submit"
Write-Host "  奇安信威胁情报: https://ti.qianxin.com/v2/search?type=file&search=$sha256"
Write-Host "  VirSCAN:        https://www.virscan.org/"
Write-Host "  360威胁情报:   https://ti.360.net/query?type=file&q=$sha256"
Write-Host ""

Write-Host ""
Write-Host "========== Summary =========="
Write-Host "SHA256: $sha256"
Write-Host ""
Write-Host "===== Quick Links ====="
Write-Host "VirusTotal:        https://www.virustotal.com/gui/file/$sha256"
Write-Host "Hybrid Analysis:   https://www.hybrid-analysis.com/sample/$sha256"
Write-Host "ANY.RUN:           https://any.run/report/hash/$sha256"
Write-Host "MetaDefender:      https://metadefender.opswat.com/results/file/$sha256"
Write-Host "微步在线:          https://s.threatbook.cn/report/file/$sha256"
Write-Host ""
Write-Host "===== Recommended Upload Order ====="
Write-Host "1. VirusTotal    - Quick multi-engine scan (70+ AVs)"
Write-Host "2. Hybrid Analysis - Deep behavioral analysis"
Write-Host "3. ANY.RUN       - Interactive sandbox (see live behavior)"
Write-Host "4. 微步在线      - Chinese AV coverage"
