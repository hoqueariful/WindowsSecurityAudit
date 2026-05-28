function Invoke-EnterpriseSecurityScan {
<#
.SYNOPSIS
    Performs a full enterprise-wide security scan combining AD, endpoint, and cloud checks.
.DESCRIPTION
    Top-level function for enterprise assessments. Coordinates AD auditing,
    multi-system scanning, compliance checks, and cloud security evaluation.
    Designed for security teams running periodic enterprise assessments.
.PARAMETER Targets
    Array of computer names. If empty, queries all enabled AD computers.
.PARAMETER OutputPath
    Report output directory. Default: Documents folder.
.EXAMPLE
    Invoke-EnterpriseSecurityScan
    Invoke-EnterpriseSecurityScan -Targets "SERVER01","SERVER02" -OutputPath "\\fileserver\reports"
#>
    [CmdletBinding()]
    param(
        [string[]]$Targets,
        [string]$OutputPath = "$env:USERPROFILE\Documents",
        [PSCredential]$Credential
    )

    $ScanStart = Get-Date
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║   Enterprise Security Scan — $(Get-Date -Format 'yyyy-MM-dd')          ║" -ForegroundColor Magenta
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Magenta

    $Report = [ordered]@{
        ScanId    = [System.Guid]::NewGuid().ToString()
        StartTime = $ScanStart
        Initiator = "$env:USERDOMAIN\$env:USERNAME"
        Phases    = [ordered]@{}
    }

    # Phase 1: Active Directory
    Write-Host "  PHASE 1: Active Directory Assessment" -ForegroundColor Cyan
    try {
        $Report.Phases['ActiveDirectory'] = @{
            Backdoors       = Find-ADBackdoors
            Vulnerabilities = Find-ADVulnerabilities
            StaleObjects    = Find-StaleADObjects
            PrivilegedAccts = Get-ADPrivilegedAccounts
        }
        Write-Host "  AD phase complete." -ForegroundColor Green
    } catch { Write-Warning "AD phase failed: $_" }

    # Phase 2: Local System Assessment
    Write-Host "  PHASE 2: Local System Assessment" -ForegroundColor Cyan
    $Report.Phases['LocalSystem'] = Invoke-SecurityAssessment -Scope Quick -OutputPath $OutputPath

    # Phase 3: Compliance
    Write-Host "  PHASE 3: Compliance Checks" -ForegroundColor Cyan
    $Report.Phases['Compliance'] = Get-ComplianceReport

    # Phase 4: Multi-system (if targets provided)
    if ($Targets -and $Targets.Count -gt 0) {
        Write-Host "  PHASE 4: Remote System Scan ($($Targets.Count) targets)" -ForegroundColor Cyan
        $RemoteParams = @{ ComputerName = $Targets }
        if ($Credential) { $RemoteParams['Credential'] = $Credential }
        $Report.Phases['RemoteSystems'] = Get-MultiSystemAudit @RemoteParams
    }

    $Report.EndTime  = Get-Date
    $Report.Duration = ($Report.EndTime - $ScanStart).ToString('hh\:mm\:ss')

    $OutFile = Join-Path $OutputPath "EnterpriseScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $Report | ConvertTo-Json -Depth 10 | Out-File $OutFile -Encoding UTF8

    Write-Host ""
    Write-Host "  Enterprise scan complete. Duration: $($Report.Duration)" -ForegroundColor Green
    Write-Host "  Report: $OutFile" -ForegroundColor Cyan

    return [PSCustomObject]$Report
}
