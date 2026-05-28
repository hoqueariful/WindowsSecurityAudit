function Get-MultiSystemAudit {
<#
.SYNOPSIS
    Runs security checks across multiple remote Windows systems in parallel.
.DESCRIPTION
    Uses PowerShell Remoting (WinRM) to audit multiple computers simultaneously.
    Aggregates findings into a consolidated multi-system report.
.PARAMETER ComputerName
    Array of computer names or IPs to audit.
.PARAMETER Credential
    PSCredential for remote authentication. If not specified, uses current user.
.PARAMETER ThrottleLimit
    Maximum concurrent sessions. Default: 10.
.EXAMPLE
    Get-MultiSystemAudit -ComputerName "PC01","PC02","PC03"
    Get-MultiSystemAudit -ComputerName (Get-ADComputer -Filter *).Name -ThrottleLimit 20
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerName,
        [PSCredential]$Credential,
        [int]$ThrottleLimit = 10
    )

    $Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $JobParams = @{ ThrottleLimit = $ThrottleLimit }
    if ($Credential) { $JobParams['Credential'] = $Credential }

    Write-Host "  Multi-System Audit: $($ComputerName.Count) target(s)" -ForegroundColor Cyan

    $ScriptBlock = {
        $Finding = [PSCustomObject]@{
            Hostname        = $env:COMPUTERNAME
            Status          = 'Success'
            OSVersion       = (Get-CimInstance Win32_OperatingSystem).Caption
            PendingReboots  = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
            DefenderEnabled = $false
            LocalAdminCount = 0
            OpenPorts       = @()
            ErrorMessage    = $null
        }

        try {
            $WD = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $Finding.DefenderEnabled = $WD.RealTimeProtectionEnabled
        } catch {}

        try {
            $Finding.LocalAdminCount = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Count
        } catch {}

        return $Finding
    }

    $Jobs = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -AsJob @JobParams
    $Jobs | Wait-Job | Receive-Job | ForEach-Object { $Results.Add($_) }

    Write-Host "  Completed: $($Results.Count)/$($ComputerName.Count) systems audited." -ForegroundColor Green
    return $Results
}
