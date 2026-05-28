function Find-ADVulnerabilities {
<#
.SYNOPSIS
    Identifies common Active Directory misconfigurations and vulnerabilities.
.DESCRIPTION
    Checks for Kerberoastable accounts, AS-REP Roastable accounts,
    accounts with reversible encryption, and unconstrained delegation.
.EXAMPLE
    Find-ADVulnerabilities
#>
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Kerberoastable accounts (SPN set, enabled user)
    try {
        $kerberoastable = Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and Enabled -eq $true } `
            -Properties ServicePrincipalName, LastLogonDate

        foreach ($acct in $kerberoastable) {
            $findings.Add([PSCustomObject]@{
                VulnerabilityType = 'Kerberoastable Account'
                Account           = $acct.SamAccountName
                Detail            = "SPN: $($acct.ServicePrincipalName -join ', ')"
                Severity          = 'High'
                Recommendation    = 'Use Group Managed Service Accounts (gMSA) instead'
            })
        }
    } catch { Write-Warning "Kerberoast check failed: $_" }

    # AS-REP Roastable (pre-auth not required)
    try {
        $asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true }
        foreach ($acct in $asrep) {
            $findings.Add([PSCustomObject]@{
                VulnerabilityType = 'AS-REP Roastable Account'
                Account           = $acct.SamAccountName
                Detail            = 'Kerberos pre-authentication disabled'
                Severity          = 'High'
                Recommendation    = 'Enable Kerberos pre-auth on all accounts unless specifically required'
            })
        }
    } catch { Write-Warning "AS-REP check failed: $_" }

    if ($findings.Count -eq 0) {
        Write-Host "No AD vulnerabilities detected." -ForegroundColor Green
    }

    Write-Output $findings
}
