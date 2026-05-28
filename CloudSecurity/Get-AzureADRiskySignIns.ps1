function Get-AzureADRiskySignIns {
<#
.SYNOPSIS
    Retrieves risky sign-ins from Azure Active Directory Identity Protection.
.DESCRIPTION
    Queries Microsoft Graph API for sign-ins flagged as risky by Azure AD.
    Requires AzureAD or Microsoft.Graph module and appropriate permissions.
.PARAMETER TenantId
    Azure AD tenant ID.
.PARAMETER RiskLevel
    Minimum risk level to retrieve: low, medium, high. Default: medium.
.EXAMPLE
    Get-AzureADRiskySignIns -TenantId "your-tenant-id"
#>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [ValidateSet('low','medium','high')]
        [string]$RiskLevel = 'medium'
    )

    # Check for Microsoft.Graph module
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Identity.SignIns' -ErrorAction SilentlyContinue)) {
        Write-Warning "Microsoft.Graph module not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
        return $null
    }

    try {
        $RiskLevels = @{ 'low'=0; 'medium'=1; 'high'=2 }
        $MinLevel   = $RiskLevels[$RiskLevel]

        Connect-MgGraph -TenantId $TenantId -Scopes 'IdentityRiskyUser.Read.All','AuditLog.Read.All' -ErrorAction Stop

        $Filter     = "riskLevelDuringSignIn ne 'none'"
        $SignIns    = Get-MgAuditLogSignIn -Filter $Filter -Top 200 -ErrorAction SilentlyContinue

        $Results = $SignIns | Where-Object {
            $RiskLevels[$_.RiskLevelDuringSignIn] -ge $MinLevel
        } | ForEach-Object {
            [PSCustomObject]@{
                UserPrincipalName   = $_.UserPrincipalName
                SignInDateTime      = $_.CreatedDateTime
                RiskLevel           = $_.RiskLevelDuringSignIn
                RiskState           = $_.RiskState
                IPAddress           = $_.IPAddress
                Location            = "$($_.Location.City), $($_.Location.CountryOrRegion)"
                AppDisplayName      = $_.AppDisplayName
                ConditionalAccess   = $_.ConditionalAccessStatus
                Status              = $_.Status.ErrorCode
            }
        }

        Write-Host "  Azure AD Risky Sign-Ins ($RiskLevel+): $($Results.Count) found." -ForegroundColor $(if ($Results.Count -gt 0) {'Red'} else {'Green'})
        return $Results
    }
    catch {
        Write-Warning "Failed to query Azure AD: $_"
        Write-Host "  Ensure you have IdentityRiskyUser.Read.All permission in Azure AD." -ForegroundColor Yellow
        return $null
    }
}
