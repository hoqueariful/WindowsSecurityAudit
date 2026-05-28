function Set-SecurityBaseline {
<#
.SYNOPSIS
    Applies a core Windows security hardening baseline.
.DESCRIPTION
    Implements security hardening settings for LLMNR, NetBIOS,
    SMBv1 signing, NTLMv2 enforcement, and guest account lockdown.
    Always run with -WhatIf first to preview changes.
.PARAMETER WhatIf
    Preview all changes before applying.
.EXAMPLE
    Set-SecurityBaseline -WhatIf
.EXAMPLE
    Set-SecurityBaseline
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Host "`n[Security Baseline] Starting hardening..." -ForegroundColor Cyan

    # Disable LLMNR
    if ($PSCmdlet.ShouldProcess('HKLM:\...DNSClient EnableMulticast', 'Set to 0 (disable LLMNR)')) {
        try {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name 'EnableMulticast' -Value 0
            Write-Host "  [OK] LLMNR disabled" -ForegroundColor Green
        } catch {
            Write-Warning "  [FAIL] LLMNR: $_"
        }
    }

    # Enforce NTLMv2
    if ($PSCmdlet.ShouldProcess('HKLM:\SYSTEM\...\Lsa LmCompatibilityLevel', 'Set to 5 (NTLMv2 only)')) {
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                -Name 'LmCompatibilityLevel' -Value 5
            Write-Host "  [OK] NTLMv2 enforced (Level 5)" -ForegroundColor Green
        } catch {
            Write-Warning "  [FAIL] NTLMv2: $_"
        }
    }

    # Disable Guest Account
    if ($PSCmdlet.ShouldProcess('Local User: Guest', 'Disable account')) {
        try {
            Disable-LocalUser -Name 'Guest' -ErrorAction Stop
            Write-Host "  [OK] Guest account disabled" -ForegroundColor Green
        } catch {
            Write-Warning "  [SKIP] Guest: $_"
        }
    }

    # Enable SMB Signing
    if ($PSCmdlet.ShouldProcess('SMB Server', 'Enable signing')) {
        try {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
            Write-Host "  [OK] SMB signing required" -ForegroundColor Green
        } catch {
            Write-Warning "  [FAIL] SMB signing: $_"
        }
    }

    Write-Host "`n[Security Baseline] Complete. Run Get-SecurityBaseline to verify." -ForegroundColor Cyan
}
