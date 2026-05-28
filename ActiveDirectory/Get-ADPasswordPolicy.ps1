function Get-ADPasswordPolicy {
<#
.SYNOPSIS
    Retrieves and evaluates the Active Directory password policy.
.DESCRIPTION
    Returns the Default Domain Password Policy and assesses it against
    NIST SP 800-63B and CIS Benchmark recommendations.
.EXAMPLE
    Get-ADPasswordPolicy
#>
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found. Install RSAT."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

        $assessments = [System.Collections.Generic.List[PSCustomObject]]::new()

        function Assess($Control, $Current, $Recommended, $Status, $Note) {
            $assessments.Add([PSCustomObject]@{
                Control     = $Control
                Current     = $Current
                Recommended = $Recommended
                Status      = $Status
                Note        = $Note
            })
        }

        Assess 'Min Password Length' $policy.MinPasswordLength '14+' `
            $(if ($policy.MinPasswordLength -ge 14) {'Pass'} elseif ($policy.MinPasswordLength -ge 8) {'Warning'} else {'Fail'}) `
            'NIST recommends minimum 8 chars; CIS recommends 14+'

        Assess 'Complexity Required' $policy.ComplexityEnabled 'True' `
            $(if ($policy.ComplexityEnabled) {'Pass'} else {'Fail'}) `
            'Requires uppercase, lowercase, digit, and symbol'

        Assess 'Max Password Age (days)' $policy.MaxPasswordAge.Days '90 or Never' `
            $(if ($policy.MaxPasswordAge.Days -le 365 -and $policy.MaxPasswordAge.Days -gt 0) {'Pass'} else {'Warning'}) `
            'NIST 800-63B: Only require changes when compromise suspected'

        Assess 'Min Password Age (days)' $policy.MinPasswordAge.Days '1' `
            $(if ($policy.MinPasswordAge.Days -ge 1) {'Pass'} else {'Warning'}) `
            'Prevents immediate password cycling to reuse old passwords'

        Assess 'Password History' $policy.PasswordHistoryCount '24' `
            $(if ($policy.PasswordHistoryCount -ge 24) {'Pass'} elseif ($policy.PasswordHistoryCount -ge 12) {'Warning'} else {'Fail'}) `
            'Prevents reuse of recent passwords'

        Assess 'Account Lockout Threshold' $policy.LockoutThreshold '5 or fewer' `
            $(if ($policy.LockoutThreshold -gt 0 -and $policy.LockoutThreshold -le 5) {'Pass'} elseif ($policy.LockoutThreshold -eq 0) {'Fail'} else {'Warning'}) `
            'Zero means no lockout — brute force risk'

        Assess 'Lockout Duration (mins)' $policy.LockoutDuration.TotalMinutes '15+' `
            $(if ($policy.LockoutDuration.TotalMinutes -ge 15) {'Pass'} else {'Warning'}) `
            'Duration before automatic unlock'

        Write-Output $assessments
    } catch {
        Write-Warning "Could not retrieve password policy: $_"
    }
}
