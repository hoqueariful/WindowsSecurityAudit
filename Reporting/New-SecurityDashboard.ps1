function New-SecurityDashboard {
<#
.SYNOPSIS
    Generates an HTML security dashboard for the local system.
.DESCRIPTION
    Runs a full set of security checks and outputs a styled HTML report
    suitable for sharing with management or including in documentation.
.PARAMETER OutputPath
    Path where the HTML report will be saved. Defaults to the Desktop.
.EXAMPLE
    New-SecurityDashboard
.EXAMPLE
    New-SecurityDashboard -OutputPath C:\Reports\security.html
#>
    [CmdletBinding()]
    param(
        [string]$OutputPath = "$env:USERPROFILE\Desktop\SecurityDashboard_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )

    Write-Host "Collecting security data..." -ForegroundColor Cyan

    $sysInfo  = Get-SystemInfo
    $baseline = Get-SecurityBaseline
    $persist  = Find-PersistenceMechanisms
    $network  = Find-NetworkAnomalies
    $cisCheck = Test-CISBenchmark

    $passCount = @($baseline | Where-Object {$_.Status -eq 'Pass'}).Count
    $failCount = @($baseline | Where-Object {$_.Status -eq 'Fail'}).Count
    $warnCount = @($baseline | Where-Object {$_.Status -eq 'Warning'}).Count

    $cisPassed = @($cisCheck | Where-Object {$_.Status -eq 'Pass'}).Count
    $cisFailed = @($cisCheck | Where-Object {$_.Status -eq 'Fail'}).Count

    $baselineRows = ($baseline | ForEach-Object {
        $color = switch ($_.Status) {
            'Pass'    { '#d4edda' }
            'Fail'    { '#f8d7da' }
            'Warning' { '#fff3cd' }
            default   { '#ffffff' }
        }
        "<tr style='background:$color'>
            <td>$($_.Control)</td>
            <td>$($_.Status)</td>
            <td>$($_.Detail)</td>
        </tr>"
    }) -join "`n"

    $persistRows = if ($persist.Count -gt 0) {
        ($persist | ForEach-Object {
            "<tr style='background:#f8d7da'>
                <td>$($_.PersistenceType)</td>
                <td>$($_.Name)</td>
                <td>$($_.Severity)</td>
                <td>$($_.Recommendation)</td>
            </tr>"
        }) -join "`n"
    } else {
        "<tr><td colspan='4' style='color:green;font-weight:bold'>No persistence mechanisms detected</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Dashboard — $($sysInfo.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }
        .header { background: linear-gradient(135deg, #0f3460, #16213e); padding: 30px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #00d4ff; }
        .header h1 { margin: 0; font-size: 28px; color: #00d4ff; }
        .header p  { margin: 5px 0 0; color: #aaa; }
        .cards { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; flex: 1; min-width: 150px; text-align: center; border-top: 3px solid #00d4ff; }
        .card .num { font-size: 36px; font-weight: bold; }
        .card .lbl { font-size: 12px; color: #aaa; margin-top: 5px; }
        .pass  { color: #28a745; } .fail { color: #dc3545; } .warn { color: #ffc107; }
        .section { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .section h2 { color: #00d4ff; margin-top: 0; font-size: 18px; border-bottom: 1px solid #0f3460; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #0f3460; color: #00d4ff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #0f3460; }
        .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows Security Dashboard</h1>
        <p>Host: $($sysInfo.ComputerName) &nbsp;|&nbsp; OS: $($sysInfo.OSName) &nbsp;|&nbsp; Generated: $($sysInfo.CollectedAt)</p>
        <p>User: $($sysInfo.LoggedOnUser) &nbsp;|&nbsp; Domain: $($sysInfo.Domain)</p>
    </div>

    <div class="cards">
        <div class="card"><div class="num pass">$passCount</div><div class="lbl">Baseline PASS</div></div>
        <div class="card"><div class="num fail">$failCount</div><div class="lbl">Baseline FAIL</div></div>
        <div class="card"><div class="num warn">$warnCount</div><div class="lbl">Warnings</div></div>
        <div class="card"><div class="num pass">$cisPassed</div><div class="lbl">CIS Passed</div></div>
        <div class="card"><div class="num fail">$cisFailed</div><div class="lbl">CIS Failed</div></div>
        <div class="card"><div class="num $(if ($persist.Count -gt 0){'fail'}else{'pass'})">$($persist.Count)</div><div class="lbl">Persistence Findings</div></div>
        <div class="card"><div class="num $(if ($network.Count -gt 0){'warn'}else{'pass'})">$($network.Count)</div><div class="lbl">Network Anomalies</div></div>
    </div>

    <div class="section">
        <h2>Security Baseline Checks</h2>
        <table>
            <tr><th>Control</th><th>Status</th><th>Detail</th></tr>
            $baselineRows
        </table>
    </div>

    <div class="section">
        <h2>Persistence Mechanism Scan</h2>
        <table>
            <tr><th>Type</th><th>Name</th><th>Severity</th><th>Recommendation</th></tr>
            $persistRows
        </table>
    </div>

    <div class="section">
        <h2>System Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>OS</td><td>$($sysInfo.OSName)</td></tr>
            <tr><td>Version</td><td>$($sysInfo.OSVersion) (Build $($sysInfo.OSBuildNumber))</td></tr>
            <tr><td>Last Boot</td><td>$($sysInfo.LastBootTime)</td></tr>
            <tr><td>PowerShell</td><td>$($sysInfo.PowerShellVersion)</td></tr>
            <tr><td>RAM</td><td>$($sysInfo.TotalMemoryGB) GB</td></tr>
            <tr><td>Recent Hotfixes</td><td>$($sysInfo.Last5Hotfixes)</td></tr>
        </table>
    </div>

    <div class="footer">
        Windows Security Audit Module v1.0.0 &nbsp;|&nbsp;
        github.com/hoqueariful/WindowsSecurityAudit &nbsp;|&nbsp;
        Generated by PowerShell on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Dashboard saved: $OutputPath" -ForegroundColor Green

    [PSCustomObject]@{
        ReportPath = $OutputPath
        GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        ComputerName = $sysInfo.ComputerName
    }
}
