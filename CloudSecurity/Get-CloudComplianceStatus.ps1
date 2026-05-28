function Get-CloudComplianceStatus {
<#
.SYNOPSIS
    Checks Azure subscription and resource compliance status via Azure Policy.
.DESCRIPTION
    Queries Azure Policy compliance states for the current subscription.
    Requires Az.PolicyInsights module and Azure login.
.EXAMPLE
    Get-CloudComplianceStatus
#>
    [CmdletBinding()]
    param(
        [string]$SubscriptionId
    )

    if (-not (Get-Module -ListAvailable -Name 'Az.PolicyInsights' -ErrorAction SilentlyContinue)) {
        Write-Warning "Az.PolicyInsights not installed. Run: Install-Module Az.PolicyInsights"
        return $null
    }

    try {
        if ($SubscriptionId) {
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        }

        $PolicyStates = Get-AzPolicyState -ErrorAction Stop |
            Group-Object ComplianceState |
            ForEach-Object {
                [PSCustomObject]@{
                    State       = $_.Name
                    Count       = $_.Count
                    Percentage  = 0
                }
            }

        $Total = ($PolicyStates | Measure-Object Count -Sum).Sum
        foreach ($State in $PolicyStates) {
            $State.Percentage = [math]::Round(($State.Count / $Total) * 100, 1)
        }

        $Compliant    = ($PolicyStates | Where-Object State -eq 'Compliant').Count
        $NonCompliant = ($PolicyStates | Where-Object State -eq 'NonCompliant').Count
        $Pct          = if ($Total -gt 0) { [math]::Round(($Compliant / $Total) * 100, 1) } else { 0 }

        Write-Host "  Azure Policy Compliance: $Compliant/$Total resources compliant ($Pct%)" -ForegroundColor $(if ($Pct -ge 80) {'Green'} elseif ($Pct -ge 60) {'Yellow'} else {'Red'})

        return [PSCustomObject]@{
            Compliant    = $Compliant
            NonCompliant = $NonCompliant
            Total        = $Total
            Percentage   = $Pct
            Details      = $PolicyStates
        }
    }
    catch { Write-Warning "Azure Policy query failed: $_"; return $null }
}
