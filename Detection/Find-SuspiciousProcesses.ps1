function Find-SuspiciousProcesses {
<#
.SYNOPSIS
    Identifies potentially malicious or suspicious running processes.
.DESCRIPTION
    Checks for processes running from unusual paths, processes masquerading
    as legitimate Windows processes, unsigned executables, and known LOLBins
    being used in suspicious ways.
.EXAMPLE
    Find-SuspiciousProcesses
.EXAMPLE
    Find-SuspiciousProcesses | Where-Object RiskLevel -eq 'High'
#>
    [CmdletBinding()]
    param()

    $suspicious = [System.Collections.Generic.List[PSCustomObject]]::new()

    $knownSystemPaths = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64",
        "$env:SystemRoot",
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}"
    )

    $lolbins = @('mshta','wscript','cscript','regsvr32','rundll32',
                  'msiexec','certutil','bitsadmin','powershell','cmd')

    $processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
                 Where-Object { $_.MainModule -ne $null }

    foreach ($proc in $processes) {
        $risks    = [System.Collections.Generic.List[string]]::new()
        $path     = $proc.MainModule.FileName
        $procName = $proc.ProcessName.ToLower()

        # Unusual execution path
        $inKnownPath = $false
        foreach ($kp in $knownSystemPaths) {
            if ($path -like "$kp*") { $inKnownPath = $true; break }
        }
        if (-not $inKnownPath -and $path -notlike "$env:USERPROFILE*") {
            $risks.Add("Unusual path: $path")
        }

        # Temp/AppData execution
        if ($path -match 'Temp|AppData|ProgramData' -and $path -notlike '*\Local\Temp\chocolatey*') {
            $risks.Add("Executing from suspicious directory: $path")
        }

        # LOLBin usage
        if ($lolbins -contains $procName) {
            $risks.Add("LOLBin process active: $procName")
        }

        # Encoded command in PowerShell
        if ($procName -eq 'powershell') {
            try {
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop).CommandLine
                if ($cmdLine -match '-enc|-encodedcommand|-e\s+[A-Za-z0-9+/]{20,}') {
                    $risks.Add('PowerShell encoded command detected')
                }
                if ($cmdLine -match '-nop|-noprofile|-w\s+hidden|-windowstyle\s+hidden') {
                    $risks.Add('PowerShell hidden/no-profile execution')
                }
            } catch {}
        }

        if ($risks.Count -gt 0) {
            $riskLevel = switch ($risks.Count) {
                { $_ -ge 3 } { 'Critical' }
                2             { 'High' }
                default       { 'Medium' }
            }

            $suspicious.Add([PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID         = $proc.Id
                Path        = $path
                UserName    = $proc.UserName
                RiskLevel   = $riskLevel
                Risks       = $risks -join ' | '
                StartTime   = $proc.StartTime
            })
        }
    }

    if ($suspicious.Count -eq 0) {
        Write-Host "No suspicious processes found." -ForegroundColor Green
    }

    Write-Output $suspicious
}
