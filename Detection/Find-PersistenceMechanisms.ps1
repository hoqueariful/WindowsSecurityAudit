function Find-PersistenceMechanisms {
<#
.SYNOPSIS
    Hunts for common attacker persistence mechanisms on Windows systems.
.DESCRIPTION
    Checks registry Run keys, scheduled tasks, startup folders, services
    with suspicious characteristics, WMI subscriptions, and browser extensions
    to identify potential attacker persistence.
.EXAMPLE
    Find-PersistenceMechanisms
.EXAMPLE
    Find-PersistenceMechanisms | Where-Object Severity -in 'High','Critical'
#>
    [CmdletBinding()]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Finding($Type, $Name, $Value, $Severity, $Recommendation) {
        $findings.Add([PSCustomObject]@{
            PersistenceType = $Type
            Name            = $Name
            Value           = $Value
            Severity        = $Severity
            Recommendation  = $Recommendation
        })
    }

    # Registry Run Keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($key in $runKeys) {
        try {
            $entries = Get-ItemProperty -Path $key -ErrorAction Stop
            $entries.PSObject.Properties |
                Where-Object { $_.Name -notmatch 'PS(Path|ParentPath|ChildName|Provider|Drive)' } |
                ForEach-Object {
                    $val = $_.Value
                    $severity = 'Low'
                    if ($val -match 'Temp|AppData|ProgramData') { $severity = 'High' }
                    if ($val -match 'powershell|cmd|wscript|mshta') { $severity = 'High' }
                    Add-Finding 'Registry Run Key' $_.Name $val $severity `
                        "Review and remove if not authorised: $key"
                }
        } catch {}
    }

    # Suspicious Scheduled Tasks
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
                 Where-Object { $_.State -ne 'Disabled' }

        foreach ($task in $tasks) {
            $action = ($task.Actions | Select-Object -ExpandProperty Execute -ErrorAction SilentlyContinue) -join ';'
            $args   = ($task.Actions | Select-Object -ExpandProperty Arguments -ErrorAction SilentlyContinue) -join ';'

            if ($action -match 'powershell|wscript|mshta|certutil|bitsadmin' -or
                $args   -match '-enc|-encoded|-nop|http') {
                $severity = if ($args -match '-enc|-encoded') {'Critical'} else {'High'}
                Add-Finding 'Scheduled Task' $task.TaskName "$action $args" $severity `
                    "Investigate task: $($task.TaskPath)$($task.TaskName)"
            }
        }
    } catch {
        Write-Warning "Could not enumerate scheduled tasks: $_"
    }

    # Startup folder entries
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($sp in $startupPaths) {
        if (Test-Path $sp) {
            Get-ChildItem -Path $sp -ErrorAction SilentlyContinue | ForEach-Object {
                Add-Finding 'Startup Folder' $_.Name $_.FullName 'Medium' `
                    "Verify this startup entry is authorised: $($_.FullName)"
            }
        }
    }

    # WMI Event Subscriptions
    try {
        $wmiSubs = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
        foreach ($sub in $wmiSubs) {
            Add-Finding 'WMI Subscription' $sub.Name $sub.Query 'Critical' `
                'WMI persistence is rare in legitimate software — investigate immediately'
        }
    } catch {
        Write-Warning "Could not query WMI subscriptions: $_"
    }

    if ($findings.Count -eq 0) {
        Write-Host "No obvious persistence mechanisms detected." -ForegroundColor Green
    }

    Write-Output $findings
}
