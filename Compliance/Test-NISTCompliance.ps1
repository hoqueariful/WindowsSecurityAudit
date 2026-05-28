function Test-NISTCompliance {
<#
.SYNOPSIS
    Evaluates system against NIST SP 800-53 and NIST CSF controls.
.DESCRIPTION
    Maps Windows security settings to NIST 800-53 control families:
    AC (Access Control), AU (Audit), CM (Configuration Management),
    IA (Identification and Authentication), SC (System Communications).
.EXAMPLE
    Test-NISTCompliance
#>
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-NISTResult($ControlId, $Family, $Control, $Status, $Evidence, $Remediation) {
        $results.Add([PSCustomObject]@{
            NIST_Control  = $ControlId
            Family        = $Family
            Control       = $Control
            Status        = $Status
            Evidence      = $Evidence
            Remediation   = $Remediation
        })
    }

    # AC-2 Account Management — check for stale local accounts
    try {
        $cutoff     = (Get-Date).AddDays(-90)
        $staleLocal = Get-LocalUser | Where-Object {
            $_.Enabled -and $_.LastLogon -lt $cutoff -and $_.LastLogon -ne $null
        }
        $status = if ($staleLocal.Count -eq 0) {'Pass'} else {'Fail'}
        Add-NISTResult 'AC-2' 'Access Control' 'Account Management' $status `
            "$($staleLocal.Count) local accounts inactive 90+ days" `
            'Disable or remove unused local accounts'
    } catch {
        Add-NISTResult 'AC-2' 'Access Control' 'Account Management' 'Warning' 'Could not enumerate local accounts' 'Run as Administrator'
    }

    # AU-2 Audit Events — verify Security log is collecting events
    try {
        $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
        $status = if ($secLog.RecordCount -gt 0) {'Pass'} else {'Fail'}
        Add-NISTResult 'AU-2' 'Audit and Accountability' 'Audit Events' $status `
            "Security log contains $($secLog.RecordCount) records. Max size: $([math]::Round($secLog.MaximumSizeInBytes/1MB))MB" `
            'Ensure Security audit log is enabled and appropriately sized'
    } catch {
        Add-NISTResult 'AU-2' 'Audit and Accountability' 'Audit Events' 'Warning' 'Could not query Security log' 'Verify event log service'
    }

    # CM-6 Configuration Settings — check audit policy
    try {
        $auditPol = & auditpol /get /category:* 2>$null
        $logonAudit = $auditPol | Select-String 'Logon'
        $status     = if ($logonAudit -match 'Success and Failure') {'Pass'} else {'Warning'}
        Add-NISTResult 'CM-6' 'Configuration Management' 'Security Audit Policy — Logon' $status `
            ($logonAudit -join '; ') `
            'Enable Success and Failure auditing for Logon events'
    } catch {
        Add-NISTResult 'CM-6' 'Configuration Management' 'Audit Policy' 'Warning' 'auditpol not accessible' 'Run as Administrator'
    }

    # IA-5 Authenticator Management — check password complexity
    try {
        $secPolicy = & net accounts 2>$null
        $complexity = $secPolicy | Select-String 'password complexity'
        Add-NISTResult 'IA-5' 'Identification and Authentication' 'Password Complexity' `
            $(if ($complexity) {'Pass'} else {'Warning'}) `
            ($complexity -join '') `
            'Enforce password complexity requirements'
    } catch {
        Add-NISTResult 'IA-5' 'Identification and Authentication' 'Password Management' 'Warning' 'Could not check policy' 'Run as Administrator'
    }

    # SC-8 Transmission Confidentiality — TLS 1.2 enabled
    try {
        $tls12 = Get-ItemProperty `
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' `
            -ErrorAction Stop
        $enabled = $tls12.Enabled
        $status  = if ($enabled -ne 0) {'Pass'} else {'Fail'}
        Add-NISTResult 'SC-8' 'System and Communications' 'TLS 1.2 Server Enabled' $status "Enabled = $enabled" `
            'Enable TLS 1.2 for encrypted communications'
    } catch {
        Add-NISTResult 'SC-8' 'System and Communications' 'TLS 1.2' 'Warning' 'Registry key absent (may be default-enabled on Windows 10/2016+)' `
            'Explicitly configure TLS 1.2 and disable TLS 1.0/1.1'
    }

    $passed = @($results | Where-Object {$_.Status -eq 'Pass'}).Count
    $failed = @($results | Where-Object {$_.Status -eq 'Fail'}).Count
    Write-Host "NIST Compliance: $passed passed, $failed failed of $($results.Count) controls" -ForegroundColor Cyan

    Write-Output $results
}
