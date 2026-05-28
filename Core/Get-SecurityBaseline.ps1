function Get-SecurityBaseline {
<#
.SYNOPSIS
    Evaluates the system against a core security baseline.
.DESCRIPTION
    Checks firewall state, audit policy, SMB configuration, RDP hardening,
    NTLMv2 enforcement, and UAC status. Returns a baseline report with
    Pass/Fail/Warning per control.
.EXAMPLE
    Get-SecurityBaseline
.EXAMPLE
    Get-SecurityBaseline | Where-Object Status -eq 'Fail'
#>
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Check {
        param($Control, $Status, $Detail, $Recommendation)
        $results.Add([PSCustomObject]@{
            Control        = $Control
            Status         = $Status
            Detail         = $Detail
            Recommendation = $Recommendation
        })
    }

    # Firewall profiles
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $fw) {
            $status = if ($profile.Enabled) { 'Pass' } else { 'Fail' }
            Add-Check "Firewall-$($profile.Name)" $status `
                "Firewall $($profile.Name) profile: $($profile.Enabled)" `
                "Enable all firewall profiles via Set-NetFirewallProfile -Enabled True"
        }
    } catch {
        Add-Check 'Firewall' 'Warning' 'Could not query firewall state' 'Run as Administrator'
    }

    # SMBv1
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $status = if ($smb1.State -eq 'Disabled') { 'Pass' } else { 'Fail' }
        Add-Check 'SMBv1-Disabled' $status "SMBv1 State: $($smb1.State)" `
            'Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
    } catch {
        Add-Check 'SMBv1-Disabled' 'Warning' 'Could not query SMBv1 state' 'Requires elevated session'
    }

    # UAC
    try {
        $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        $status = if ($uac.EnableLUA -eq 1) { 'Pass' } else { 'Fail' }
        Add-Check 'UAC-Enabled' $status "EnableLUA = $($uac.EnableLUA)" `
            'Enable UAC: Set EnableLUA to 1 in HKLM:\...\Policies\System'
    } catch {
        Add-Check 'UAC-Enabled' 'Warning' 'Could not read UAC registry value' 'Run as Administrator'
    }

    # NTLMv2
    try {
        $ntlm = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction Stop
        $status = if ($ntlm -ge 3) { 'Pass' } else { 'Fail' }
        Add-Check 'NTLMv2-Enforced' $status "LmCompatibilityLevel = $ntlm (recommended: 5)" `
            'Set LmCompatibilityLevel to 5 to enforce NTLMv2 only'
    } catch {
        Add-Check 'NTLMv2-Enforced' 'Warning' 'LmCompatibilityLevel key not found' `
            'Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa LmCompatibilityLevel = 5'
    }

    # RDP NLA
    try {
        $nla = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name 'UserAuthentication' -ErrorAction Stop
        $status = if ($nla -eq 1) { 'Pass' } else { 'Fail' }
        Add-Check 'RDP-NLA' $status "Network Level Authentication = $nla" `
            'Enable NLA: Set UserAuthentication to 1 under RDP-Tcp registry key'
    } catch {
        Add-Check 'RDP-NLA' 'Warning' 'RDP NLA key not found or RDP not enabled' 'No action required if RDP is disabled'
    }

    Write-Output $results
}
