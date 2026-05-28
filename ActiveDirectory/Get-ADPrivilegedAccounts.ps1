function Get-ADPrivilegedAccounts {
<#
.SYNOPSIS
    Enumerates all privileged Active Directory accounts and groups.
.DESCRIPTION
    Returns members of high-privilege groups including Domain Admins,
    Enterprise Admins, Schema Admins, Administrators, and Backup Operators.
    Flags accounts with risky configurations such as no password expiry,
    password not required, or Kerberos pre-auth disabled.
.EXAMPLE
    Get-ADPrivilegedAccounts
.EXAMPLE
    Get-ADPrivilegedAccounts | Where-Object PasswordNeverExpires -eq $true
#>
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not available. Install RSAT or run on a Domain Controller."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Backup Operators',
        'Account Operators',
        'Server Operators',
        'Group Policy Creator Owners'
    )

    $allAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen        = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                       Where-Object { $_.objectClass -eq 'user' }

            foreach ($member in $members) {
                if ($seen.Add($member.SamAccountName)) {
                    try {
                        $user = Get-ADUser -Identity $member.SamAccountName `
                            -Properties PasswordNeverExpires,PasswordNotRequired,
                                        DoesNotRequirePreAuth,LastLogonDate,
                                        Enabled,WhenCreated,DistinguishedName `
                            -ErrorAction Stop

                        $allAccounts.Add([PSCustomObject]@{
                            SamAccountName          = $user.SamAccountName
                            DisplayName             = $user.Name
                            PrivilegedGroup         = $group
                            Enabled                 = $user.Enabled
                            PasswordNeverExpires     = $user.PasswordNeverExpires
                            PasswordNotRequired      = $user.PasswordNotRequired
                            KerberosPreAuthDisabled  = $user.DoesNotRequirePreAuth
                            LastLogonDate            = $user.LastLogonDate
                            AccountCreated           = $user.WhenCreated
                            RiskFlags               = @(
                                if ($user.PasswordNeverExpires)    { 'NoExpiry' }
                                if ($user.PasswordNotRequired)     { 'NoPwdReq' }
                                if ($user.DoesNotRequirePreAuth)   { 'ASREPRoastable' }
                                if (-not $user.Enabled)            { 'Disabled' }
                            ) -join ', '
                        })
                    } catch {}
                }
            }
        } catch {
            Write-Warning "Could not enumerate group '$group': $_"
        }
    }

    Write-Output $allAccounts
}
