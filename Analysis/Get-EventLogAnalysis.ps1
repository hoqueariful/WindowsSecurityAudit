function Get-EventLogAnalysis {
<#
.SYNOPSIS
    Analyses Windows Event Logs for security-relevant events.
.DESCRIPTION
    Parses Security, System, and Application logs for high-priority event IDs
    including logon failures, account lockouts, policy changes, and audit log clearing.
.PARAMETER Hours
    How many hours back to analyse. Default: 24.
.PARAMETER LogName
    Log to analyse: Security, System, Application, or All. Default: Security.
.EXAMPLE
    Get-EventLogAnalysis
    Get-EventLogAnalysis -Hours 72 -LogName All
#>
    [CmdletBinding()]
    param(
        [int]$Hours       = 24,
        [ValidateSet('Security','System','Application','All')]
        [string]$LogName  = 'Security'
    )

    $StartTime  = (Get-Date).AddHours(-$Hours)
    $Results    = [System.Collections.Generic.List[PSCustomObject]]::new()

    $SecurityEventIDs = @{
        4624  = @{ Name='Successful Logon';         Severity='Info'     }
        4625  = @{ Name='Failed Logon';             Severity='High'     }
        4634  = @{ Name='Logoff';                   Severity='Info'     }
        4648  = @{ Name='Explicit Credential Logon';Severity='Medium'   }
        4657  = @{ Name='Registry Value Modified';  Severity='Medium'   }
        4663  = @{ Name='File Access Attempt';      Severity='Medium'   }
        4698  = @{ Name='Scheduled Task Created';   Severity='High'     }
        4702  = @{ Name='Scheduled Task Updated';   Severity='Medium'   }
        4720  = @{ Name='User Account Created';     Severity='High'     }
        4722  = @{ Name='User Account Enabled';     Severity='Medium'   }
        4725  = @{ Name='User Account Disabled';    Severity='Low'      }
        4726  = @{ Name='User Account Deleted';     Severity='High'     }
        4728  = @{ Name='Member Added to Group';    Severity='High'     }
        4732  = @{ Name='Member Added to Local Group';Severity='High'   }
        4740  = @{ Name='Account Locked Out';       Severity='High'     }
        4756  = @{ Name='Universal Group Member Added';Severity='High'  }
        4768  = @{ Name='Kerberos TGT Request';     Severity='Info'     }
        4769  = @{ Name='Kerberos Service Ticket';  Severity='Info'     }
        4771  = @{ Name='Kerberos Pre-Auth Failed'; Severity='High'     }
        4776  = @{ Name='NTLM Credential Validation';Severity='Medium'  }
        4778  = @{ Name='Session Reconnected';      Severity='Info'     }
        4797  = @{ Name='Query Blank Password';     Severity='High'     }
        5145  = @{ Name='Network Share Access';     Severity='Low'      }
        1102  = @{ Name='Audit Log Cleared';        Severity='Critical' }
        7045  = @{ Name='New Service Installed';    Severity='High'     }
    }

    $Logs = if ($LogName -eq 'All') { @('Security','System','Application') } else { @($LogName) }

    foreach ($Log in $Logs) {
        try {
            $FilterTable = @{
                LogName   = $Log
                StartTime = $StartTime
            }

            if ($Log -eq 'Security') {
                $FilterTable['Id'] = $SecurityEventIDs.Keys
            }

            $Events = Get-WinEvent -FilterHashtable $FilterTable -ErrorAction SilentlyContinue |
                Select-Object -First 5000

            foreach ($Event in $Events) {
                $Meta = $SecurityEventIDs[$Event.Id]
                $Results.Add([PSCustomObject]@{
                    TimeCreated  = $Event.TimeCreated
                    EventId      = $Event.Id
                    EventName    = if ($Meta) { $Meta.Name } else { 'Unknown' }
                    Severity     = if ($Meta) { $Meta.Severity } else { 'Info' }
                    LogName      = $Log
                    MachineName  = $Event.MachineName
                    Message      = $Event.Message.Substring(0, [Math]::Min(200, $Event.Message.Length))
                })
            }
        }
        catch { Write-Warning "Could not read log '$Log': $_" }
    }

    $Summary = $Results | Group-Object Severity | Sort-Object Name
    Write-Host "  Event Log Analysis ($Hours hours)" -ForegroundColor Cyan
    Write-Host "  Total events: $($Results.Count)" -ForegroundColor Gray
    foreach ($Group in $Summary) {
        $Color = switch ($Group.Name) { 'Critical' {'Red'} 'High' {'DarkRed'} 'Medium' {'Yellow'} default {'Gray'} }
        Write-Host "    $($Group.Name): $($Group.Count)" -ForegroundColor $Color
    }

    return $Results | Sort-Object TimeCreated -Descending
}
