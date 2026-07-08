$files = Get-ChildItem 'c:\Users\nk7\Documents\trae_projects\fish' -Filter '*.json' -Recurse | Where-Object { $_.Name -match 'win10_1903' }
foreach ($f in $files) {
    $j = Get-Content $f.FullName -Encoding UTF8 | ConvertFrom-Json
    Write-Host "=== File: $($f.Name) ==="
    Write-Host "Score: $($j.info.score)"
    Write-Host "Duration: $($j.info.duration)s"
    Write-Host "Main process: $($j.behavior.generic[0].process_name)"
    Write-Host "Signatures:"
    foreach ($proc in $j.behavior.generic) {
        Write-Host "  Process: $($proc.process_name) pid:$($proc.pid)"
        if ($proc.signatures.Count -gt 0) {
            foreach ($sig in $proc.signatures) {
                Write-Host "    - $($sig.name) severity:$($sig.severity) class:$($sig.sig_class) $($sig.description)"
            }
        }
        if ($proc.summary.dll_loaded) {
            Write-Host "    DLLs: $($proc.summary.dll_loaded -join ', ')"
        }
    }
    Write-Host "Summary detected: $($j.behavior.summary.detected -join ', ')"
    Write-Host ""
}
