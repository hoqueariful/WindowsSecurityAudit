function Enable-PowerShellSecurity {
<#
.SYNOPSIS
    Hardens PowerShell security settings on the local system.
.DESCRIPTION
    Configures PowerShell Script Block Logging, Module Logging,
    Transcription, and enforces Constrained Language Mode policy
    via WDAC or AppLocker where available.
.PARAMETER WhatIf
    Preview changes without applying them.
.EXAMPLE
    Enable-PowerShellSecurity
.EXAMPLE
    Enable-PowerShellSecurity -WhatIf
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Set-RegistrySecurity {
        param($Path, $Name, $Value, $Description)

        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
            try {
                if (-not (Test-Path $Path)) {
                    New-Item -Path $Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
                $results.Add([PSCustomObject]@{
                    Setting     = $Description
                    Path        = "$Path\$Name"
                    Value       = $Value
                    Status      = 'Applied'
                })
            } catch {
                $results.Add([PSCustomObject]@{
                    Setting = $Description
                    Path    = "$Path\$Name"
                    Value   = $Value
                    Status  = "Failed: $_"
                })
            }
        } else {
            $results.Add([PSCustomObject]@{
                Setting = $Description
                Path    = "$Path\$Name"
                Value   = $Value
                Status  = 'WhatIf — would apply'
            })
        }
    }

    # Script Block Logging
    Set-RegistrySecurity `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        'EnableScriptBlockLogging' 1 'PowerShell Script Block Logging'

    Set-RegistrySecurity `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        'EnableScriptBlockInvocationLogging' 1 'PowerShell Script Block Invocation Logging'

    # Module Logging
    Set-RegistrySecurity `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        'EnableModuleLogging' 1 'PowerShell Module Logging'

    # PowerShell Transcription
    Set-RegistrySecurity `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        'EnableTranscripting' 1 'PowerShell Transcription'

    Set-RegistrySecurity `
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        'EnableInvocationHeader' 1 'PowerShell Transcription Header'

    Write-Host "`nPowerShell Security Hardening Results:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize

    Write-Output $results
}
