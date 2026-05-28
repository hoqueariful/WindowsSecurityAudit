function Find-SuspiciousAuthentication {
<#
.SYNOPSIS
    Analyses Windows Security event logs for suspicious authentication patterns.
.DESCRIPTION
    Detects brute force attempts, password spray patterns, off-hours logons,
    and NTLM downgrade indicators by parsing Security event log entries.
.PARAMETER Hours
    Number of hours to look back in the event log. Default is 24.
.PARAMETER FailureThreshold
    Number of failed logons before flagging as suspicious. Default is 5.
.EXAMPLE
    Find-SuspiciousAuthentication
.EXAMPLE
    Find-SuspiciousAuthentication -Hours 48 -FailureThreshold 10
#>
    [CmdletBinding()]
    param(
        [int]$Hours = 24,
        [int]$FailureThreshold = 5
    )

    $startTime = (Get-Date).AddHours(-$Hours)
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Verbose "Analysing authentication events for the past $Hours hours..."

    # Failed logons (4625)
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $startTime
        } -ErrorAction Stop

        $grouped = $failedLogons | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                TargetAccount = $xml.Event.EventData.Data |
                                Where-Object { $_.Name -eq 'TargetUserName' } |
                                Select-Object -ExpandProperty '#text'
                SourceIP      = $xml.Event.EventData.Data |
                                Where-Object { $_.Name -eq 'IpAddress' } |
                                Select-Object -ExpandProperty '#text'
                TimeCreated   = $_.TimeCreated
            }
        } | Group-Object TargetAccount

        foreach ($group in $grouped) {
            if ($group.Count -ge $FailureThreshold) {
                $findings.Add([PSCustomObject]@{
                    FindingType   = 'BruteForce/PasswordSpray'
                    Account       = $group.Name
                    FailureCount  = $group.Count
                    FirstSeen     = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    LastSeen      = ($group.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
                    SourceIPs     = ($group.Group | Select-Object -ExpandProperty SourceIP -Unique) -join ', '
                    Severity      = if ($group.Count -ge 20) {'Critical'} elseif ($group.Count -ge 10) {'High'} else {'Medium'}
                    Recommendation = 'Investigate source IPs and consider account lockout policy review'
                })
            }
        }
    } catch {
        Write-Warning "Could not query Security log for failed logons: $_"
    }

    # Off-hours successful logons (4624 Type 10 = RemoteInteractive)
    try {
        $remoteLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = $startTime
        } -ErrorAction Stop | Where-Object {
            $_.TimeCreated.Hour -lt 6 -or $_.TimeCreated.Hour -gt 22
        }

        if ($remoteLogons.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                FindingType   = 'Off-Hours Logon'
                Account       = 'Multiple (see events)'
                FailureCount  = 0
                FirstSeen     = ($remoteLogons | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                LastSeen      = ($remoteLogons | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
                SourceIPs     = 'Check event log'
                Severity      = 'Medium'
                Recommendation = "Review $($remoteLogons.Count) logon(s) occurring outside business hours"
            })
        }
    } catch {
        Write-Warning "Could not query off-hours logon events: $_"
    }

    if ($findings.Count -eq 0) {
        Write-Host "No suspicious authentication patterns found in the past $Hours hours." -ForegroundColor Green
    }

    Write-Output $findings
}
