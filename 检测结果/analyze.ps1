$j1 = Get-Content 'c:\Users\nk7\Documents\trae_projects\fish\检测结果\win10_1903_x64_2016_a207a1828e6bdbbf162b12d4a836aabb8f5772b2cdda74ff053e112ba2bc97ef_1783336679.json' | ConvertFrom-Json
Write-Host "=== PDF链路 (简历.pdf.exe) ==="
Write-Host "Score: $($j1.info.score)"
Write-Host "Duration: $($j1.info.duration)s"
Write-Host "Process: $($j1.behavior.generic[0].process_name)"
Write-Host "Signatures:"
foreach ($sig in $j1.behavior.generic[0].signatures) {
    Write-Host "  - $($sig.name) (severity:$($sig.severity), class:$($sig.sig_class)) $($sig.description)"
}
Write-Host "DLLs loaded:"
foreach ($dll in $j1.behavior.generic[0].summary.dll_loaded) {
    Write-Host "  - $dll"
}
Write-Host "API stats:"
$apis = $j1.behavior.apistats.'6792'
foreach ($key in $apis.PSObject.Properties) {
    Write-Host "  $key.Name = $key.Value"
}

Write-Host ""
Write-Host "=== LNK链路 (challenge.lnk) ==="
$j2 = Get-Content 'c:\Users\nk7\Documents\trae_projects\fish\检测结果\win10_1903_x64_2016_bb1599bb87a002ff316e72829632f8f71fcf1c955ba062a6730f1b29966fec9a_1783336615.json' | ConvertFrom-Json
Write-Host "Score: $($j2.info.score)"
Write-Host "Duration: $($j2.info.duration)s"
Write-Host "Processes:"
foreach ($proc in $j2.behavior.generic) {
    Write-Host "  - $($proc.process_name) (pid:$($proc.pid), ppid:$($proc.ppid))"
    if ($proc.signatures) {
        foreach ($sig in $proc.signatures) {
            Write-Host "    sig: $($sig.name) severity:$($sig.severity) class:$($sig.sig_class) desc:$($sig.description)"
        }
    }
}
Write-Host "Summary detected: $($j2.behavior.summary.detected)"
