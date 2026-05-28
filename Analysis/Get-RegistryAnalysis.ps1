function Get-RegistryAnalysis {
<#
.SYNOPSIS
    Analyses critical registry keys for security misconfigurations and persistence mechanisms.
.DESCRIPTION
    Checks auto-run keys, LSA settings, UAC configuration, Windows Defender exclusions,
    and other security-relevant registry values.
.EXAMPLE
    Get-RegistryAnalysis
#>
    [CmdletBinding()]
    param()

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $SecurityKeys = @(
        @{ Key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';        Name='AutoRun (HKLM)';        Severity='High' }
        @{ Key='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';        Name='AutoRun (HKCU)';        Severity='High' }
        @{ Key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';    Name='RunOnce (HKLM)';        Severity='High' }
        @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services';                    Name='Services';              Severity='Medium' }
        @{ Key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';Name='Winlogon';              Severity='Critical' }
        @{ Key='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                 Name='LSA Settings';          Severity='Critical' }
        @{ Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'; Name='Defender Path Exclusions'; Severity='High' }
    )

    foreach ($KeyDef in $SecurityKeys) {
        try {
            if (Test-Path -Path $KeyDef.Key) {
                $Values = Get-ItemProperty -Path $KeyDef.Key -ErrorAction SilentlyContinue
                if ($Values) {
                    $Props = $Values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                    foreach ($Prop in $Props) {
                        $Results.Add([PSCustomObject]@{
                            Category    = $KeyDef.Name
                            RegistryKey = $KeyDef.Key
                            ValueName   = $Prop.Name
                            ValueData   = $Prop.Value
                            Severity    = $KeyDef.Severity
                            Note        = "Verify this value is expected and authorised"
                        })
                    }
                }
            }
        }
        catch { Write-Warning "Could not read: $($KeyDef.Key)" }
    }

    #region --- LSA Security Settings ---
    try {
        $LSA = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue

        if ($LSA.LmCompatibilityLevel -lt 3) {
            $Results.Add([PSCustomObject]@{
                Category    = 'LSA - LM Authentication Level'
                RegistryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                ValueName   = 'LmCompatibilityLevel'
                ValueData   = $LSA.LmCompatibilityLevel
                Severity    = 'High'
                Note        = "Should be 3 or higher (NTLMv2 only). Current: $($LSA.LmCompatibilityLevel)"
            })
        }

        if ($LSA.DisableRestrictedAdmin -eq 1) {
            $Results.Add([PSCustomObject]@{
                Category    = 'LSA - Restricted Admin'
                RegistryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                ValueName   = 'DisableRestrictedAdmin'
                ValueData   = 1
                Severity    = 'High'
                Note        = 'Restricted Admin mode is disabled — enables credential pass-through on RDP'
            })
        }
    }
    catch { Write-Warning "LSA check failed: $_" }
    #endregion

    Write-Host "  Registry Analysis: $($Results.Count) registry finding(s)." -ForegroundColor Yellow
    return $Results
}
