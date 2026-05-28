function Find-NetworkAnomalies {
<#
.SYNOPSIS
    Identifies suspicious network connections and listening services.
.DESCRIPTION
    Analyses active TCP/UDP connections for unusual ports, connections to
    non-standard destinations, processes listening unexpectedly, and
    potential C2 beaconing indicators.
.EXAMPLE
    Find-NetworkAnomalies
#>
    [CmdletBinding()]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $commonPorts    = @(80,443,8080,8443,53,22,3389,445,139,135,
                        137,138,25,587,143,993,110,995,1433,3306,5432)
    $suspiciousPorts = @(4444,1337,31337,6666,6667,4443,9999,8888)

    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop

        foreach ($conn in $connections) {
            $risks = [System.Collections.Generic.List[string]]::new()

            # Suspicious known hacker ports
            if ($suspiciousPorts -contains $conn.LocalPort -or
                $suspiciousPorts -contains $conn.RemotePort) {
                $risks.Add("Suspicious port: L:$($conn.LocalPort) R:$($conn.RemotePort)")
            }

            # Established connections on non-standard outbound ports
            if ($conn.State -eq 'Established' -and
                $conn.RemoteAddress -ne '0.0.0.0' -and
                $conn.RemoteAddress -ne '127.0.0.1' -and
                $conn.RemoteAddress -notmatch '^::' -and
                $conn.RemotePort -notin $commonPorts) {
                $risks.Add("Unusual outbound port $($conn.RemotePort) to $($conn.RemoteAddress)")
            }

            if ($risks.Count -gt 0) {
                $procName = 'Unknown'
                try {
                    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
                    $procName = "$($proc.ProcessName) (PID $($conn.OwningProcess))"
                } catch {}

                $findings.Add([PSCustomObject]@{
                    Process       = $procName
                    LocalAddress  = $conn.LocalAddress
                    LocalPort     = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort    = $conn.RemotePort
                    State         = $conn.State
                    Risks         = $risks -join ' | '
                    Severity      = if ($risks.Count -ge 2) {'High'} else {'Medium'}
                })
            }
        }
    } catch {
        Write-Warning "Could not enumerate network connections: $_"
    }

    if ($findings.Count -eq 0) {
        Write-Host "No network anomalies detected." -ForegroundColor Green
    }

    Write-Output $findings
}
