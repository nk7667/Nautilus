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

# ===== 3. 奇安信威胁情报 / 微步在线 =====
Write-Host "===== [3/3] Chinese Threat Intelligence ====="
Write-Host "  微步在线云沙箱: https://s.threatbook.cn/"
Write-Host "  奇安信威胁情报: https://ti.qianxin.com/"
Write-Host "  VirSCAN:        https://www.virscan.org/"
Write-Host "  Jotti:          https://virusscan.jotti.org/"
Write-Host ""
Write-Host "  Please manually upload to these platforms for additional verification."

Write-Host ""
Write-Host "========== Summary =========="
Write-Host "SHA256: $sha256"
Write-Host "VirusTotal: https://www.virustotal.com/gui/file/$sha256"
Write-Host "MetaDefender: https://metadefender.opswat.com/results/file/$sha256"
