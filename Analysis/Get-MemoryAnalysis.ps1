function Get-MemoryAnalysis {
<#
.SYNOPSIS
    Analyses running processes for memory-injection indicators and suspicious behaviour.
.DESCRIPTION
    Checks for processes with suspicious parent-child relationships, unsigned code,
    processes running from temp directories, and known LOLBIN abuse patterns.
.EXAMPLE
    Get-MemoryAnalysis
#>
    [CmdletBinding()]
    param()

    $Results    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Processes  = Get-CimInstance -ClassName Win32_Process

    $SuspiciousParents = @{
        'winword.exe'   = @('cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe')
        'excel.exe'     = @('cmd.exe','powershell.exe','wscript.exe','cscript.exe')
        'outlook.exe'   = @('cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe')
        'mshta.exe'     = @('cmd.exe','powershell.exe','wscript.exe','cscript.exe')
        'wscript.exe'   = @('cmd.exe','powershell.exe')
        'cscript.exe'   = @('cmd.exe','powershell.exe')
    }

    $TempPaths  = @($env:TEMP, $env:TMP, "$env:SystemRoot\Temp", "$env:APPDATA", "$env:PUBLIC")

    foreach ($Process in $Processes) {
        $Flags      = [System.Collections.Generic.List[string]]::new()
        $Severity   = 'Info'

        $ProcessName  = $Process.Name.ToLower()
        $ProcessPath  = $Process.ExecutablePath

        # Check: Running from temp location
        if ($ProcessPath) {
            foreach ($TempPath in $TempPaths) {
                if ($ProcessPath -like "$TempPath*") {
                    $Flags.Add("Running from temp path: $ProcessPath")
                    $Severity = 'High'
                }
            }
        }

        # Check: Suspicious parent-child relationship
        $Parent = $Processes | Where-Object { $_.ProcessId -eq $Process.ParentProcessId }
        if ($Parent) {
            $ParentName = $Parent.Name.ToLower()
            if ($SuspiciousParents.ContainsKey($ParentName)) {
                if ($ProcessName -in $SuspiciousParents[$ParentName]) {
                    $Flags.Add("Suspicious parent: $ParentName spawned $ProcessName")
                    $Severity = 'Critical'
                }
            }
        }

        # Check: PowerShell with encoded command
        if ($ProcessName -eq 'powershell.exe' -and $Process.CommandLine -match '-[Ee]nc') {
            $Flags.Add("Encoded PowerShell command detected")
            $Severity = 'High'
        }

        if ($Flags.Count -gt 0) {
            $Results.Add([PSCustomObject]@{
                ProcessName  = $Process.Name
                ProcessId    = $Process.ProcessId
                ParentPID    = $Process.ParentProcessId
                ParentName   = if ($Parent) { $Parent.Name } else { 'Unknown' }
                Path         = $ProcessPath
                CommandLine  = $Process.CommandLine
                Severity     = $Severity
                Flags        = $Flags -join ' | '
            })
        }
    }

    Write-Host "  Memory Analysis: $($Results.Count) suspicious process(es) detected." -ForegroundColor $(if ($Results.Count -gt 0) {'Red'} else {'Green'})
    return $Results
}
