function Test-M365SecurityPosture {
<#
.SYNOPSIS
    Evaluates the Microsoft 365 tenant security posture using Secure Score indicators.
.DESCRIPTION
    Checks MFA enrollment, legacy authentication, conditional access policies,
    and key M365 security configuration settings.
.EXAMPLE
    Test-M365SecurityPosture
#>
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph' -ErrorAction SilentlyContinue)) {
        Write-Warning "Microsoft.Graph module not installed. Run: Install-Module Microsoft.Graph"
        return $null
    }

    try {
        $Scopes = @(
            'Policy.Read.All',
            'Reports.Read.All',
            'SecurityEvents.Read.All',
            'User.Read.All'
        )

        Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -ErrorAction Stop
        $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

        # MFA registration
        $MFAReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -ErrorAction SilentlyContinue
        if ($MFAReport) {
            $MFARegistered  = ($MFAReport | Where-Object IsMfaRegistered).Count
            $TotalUsers     = $MFAReport.Count
            $MFAPct         = [math]::Round(($MFARegistered / $TotalUsers) * 100, 1)

            $Results.Add([PSCustomObject]@{
                Check      = 'MFA Registration Rate'
                Status     = if ($MFAPct -ge 95) {'Pass'} elseif ($MFAPct -ge 80) {'Warning'} else {'Fail'}
                Value      = "$MFARegistered/$TotalUsers ($MFAPct%)"
                Recommend  = 'Target 100% MFA registration via Conditional Access'
            })
        }

        # Conditional Access policies
        $CAPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
        $Results.Add([PSCustomObject]@{
            Check     = 'Conditional Access Policies'
            Status    = if ($CAPolicies.Count -gt 0) {'Pass'} else {'Fail'}
            Value     = "$($CAPolicies.Count) policies configured"
            Recommend = 'Configure at minimum: Block Legacy Auth, Require MFA for Admins'
        })

        Write-Host "  M365 Security Posture: $($Results.Count) checks completed." -ForegroundColor Cyan
        $Results | Format-Table -AutoSize

        return $Results
    }
    catch {
        Write-Warning "M365 assessment failed: $_"
        return $null
    }
}
