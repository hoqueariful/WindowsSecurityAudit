function Test-CISBenchmark {
<#
.SYNOPSIS
    Tests system against CIS Benchmark Level 1 controls for Windows.
.DESCRIPTION
    Evaluates a prioritised subset of CIS Microsoft Windows Benchmark
    Level 1 controls covering account policies, local policies, and
    Windows Firewall settings.
.EXAMPLE
    Test-CISBenchmark
.EXAMPLE
    Test-CISBenchmark | Where-Object Status -eq 'Fail'
#>
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-CISResult($ID, $Control, $Status, $CurrentValue, $ExpectedValue, $Remediation) {
        $results.Add([PSCustomObject]@{
            CIS_ID         = $ID
            Control        = $Control
            Status         = $Status
            CurrentValue   = $CurrentValue
            ExpectedValue  = $ExpectedValue
            Remediation    = $Remediation
        })
    }

    # CIS 1.1.1 — Minimum password length
    try {
        $pwLen = (net accounts 2>$null | Select-String 'Minimum password length').ToString()
        $val   = [int]($pwLen -replace '.*?(\d+)$','$1')
        $status = if ($val -ge 14) {'Pass'} elseif ($val -ge 8) {'Warning'} else {'Fail'}
        Add-CISResult '1.1.1' 'Minimum password length' $status $val '14 or more' `
            'Set minimum password length to 14 via Local Security Policy'
    } catch {
        Add-CISResult '1.1.1' 'Minimum password length' 'Error' 'Unable to retrieve' '14+' 'Run as Administrator'
    }

    # CIS 1.2.1 — Account lockout duration
    try {
        $lockout = (net accounts 2>$null | Select-String 'Lockout duration').ToString()
        $val     = [int]($lockout -replace '.*?(\d+).*','$1')
        $status  = if ($val -ge 15) {'Pass'} elseif ($val -gt 0) {'Warning'} else {'Fail'}
        Add-CISResult '1.2.1' 'Account lockout duration (minutes)' $status $val '15 or more' `
            'Set lockout duration to 15 minutes in Account Lockout Policy'
    } catch {
        Add-CISResult '1.2.1' 'Account lockout duration' 'Error' 'Unable to retrieve' '15+' 'Run as Administrator'
    }

    # CIS 2.3.1.1 — Accounts: Administrator account status
    try {
        $admin = Get-LocalUser -Name 'Administrator' -ErrorAction Stop
        $status = if ($admin.Enabled) {'Fail'} else {'Pass'}
        Add-CISResult '2.3.1.1' 'Built-in Administrator account disabled' $status $admin.Enabled 'False (Disabled)' `
            'Disable the built-in Administrator: Disable-LocalUser -Name Administrator'
    } catch {
        Add-CISResult '2.3.1.1' 'Built-in Administrator status' 'Warning' 'Could not query' 'Disabled' 'Run as Administrator'
    }

    # CIS 2.3.1.2 — Accounts: Guest account status
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        $status = if ($guest.Enabled) {'Fail'} else {'Pass'}
        Add-CISResult '2.3.1.2' 'Built-in Guest account disabled' $status $guest.Enabled 'False (Disabled)' `
            'Disable Guest: Disable-LocalUser -Name Guest'
    } catch {
        Add-CISResult '2.3.1.2' 'Built-in Guest status' 'Warning' 'Could not query' 'Disabled' 'Run as Administrator'
    }

    # CIS 9.1.1 — Windows Firewall Domain profile
    try {
        $fwDomain  = Get-NetFirewallProfile -Name Domain  -ErrorAction Stop
        $fwPrivate = Get-NetFirewallProfile -Name Private -ErrorAction Stop
        $fwPublic  = Get-NetFirewallProfile -Name Public  -ErrorAction Stop

        foreach ($profile in @($fwDomain, $fwPrivate, $fwPublic)) {
            $status = if ($profile.Enabled) {'Pass'} else {'Fail'}
            Add-CISResult "9.x.1" "Windows Firewall $($profile.Name) enabled" $status $profile.Enabled 'True' `
                "Enable $($profile.Name) firewall: Set-NetFirewallProfile -Name $($profile.Name) -Enabled True"
        }
    } catch {
        Add-CISResult '9.x.1' 'Firewall profiles' 'Warning' 'Could not query' 'All Enabled' 'Run as Administrator'
    }

    $passed   = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failed   = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnings = @($results | Where-Object { $_.Status -eq 'Warning' }).Count

    Write-Host "`nCIS Benchmark Results: Pass=$passed  Fail=$failed  Warning=$warnings" -ForegroundColor Cyan

    Write-Output $results
}
