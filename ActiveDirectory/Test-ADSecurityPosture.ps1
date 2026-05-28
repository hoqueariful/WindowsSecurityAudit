function Test-ADSecurityPosture {
<#
.SYNOPSIS
    Runs a full Active Directory security posture assessment.
.DESCRIPTION
    Orchestrates all AD security checks into a single comprehensive report
    covering privileged accounts, password policy, stale objects,
    vulnerabilities, and potential backdoors.
.EXAMPLE
    Test-ADSecurityPosture
#>
    [CmdletBinding()]
    param()

    Write-Host "`n=== Active Directory Security Posture Assessment ===" -ForegroundColor Cyan
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

    Write-Host "[1/5] Checking password policy..." -ForegroundColor Yellow
    $pwPolicy = Get-ADPasswordPolicy

    Write-Host "[2/5] Enumerating privileged accounts..." -ForegroundColor Yellow
    $privAccounts = Get-ADPrivilegedAccounts

    Write-Host "[3/5] Finding stale objects..." -ForegroundColor Yellow
    $staleObjects = Find-StaleADObjects

    Write-Host "[4/5] Scanning for vulnerabilities..." -ForegroundColor Yellow
    $vulns = Find-ADVulnerabilities

    Write-Host "[5/5] Checking for backdoors..." -ForegroundColor Yellow
    $backdoors = Find-ADBackdoors

    Write-Host "`n=== Assessment Summary ===" -ForegroundColor Cyan
    Write-Host "Password Policy Controls : $($pwPolicy.Count)" -ForegroundColor White
    Write-Host "Privileged Accounts Found: $($privAccounts.Count)" -ForegroundColor $(if ($privAccounts.Count -gt 10) {'Red'} else {'Green'})
    Write-Host "Stale Objects Found      : $($staleObjects.Count)" -ForegroundColor $(if ($staleObjects.Count -gt 0) {'Yellow'} else {'Green'})
    Write-Host "Vulnerabilities Found    : $($vulns.Count)" -ForegroundColor $(if ($vulns.Count -gt 0) {'Red'} else {'Green'})
    Write-Host "Backdoor Indicators      : $($backdoors.Count)" -ForegroundColor $(if ($backdoors.Count -gt 0) {'Red'} else {'Green'})
    Write-Host ""

    [PSCustomObject]@{
        PasswordPolicy   = $pwPolicy
        PrivilegedAccounts = $privAccounts
        StaleObjects     = $staleObjects
        Vulnerabilities  = $vulns
        BackdoorIndicators = $backdoors
        AssessedAt       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}
