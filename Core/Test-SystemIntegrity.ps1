function Test-SystemIntegrity {
<#
.SYNOPSIS
    Checks core Windows integrity settings and security features.
.DESCRIPTION
    Validates Secure Boot, UEFI mode, BitLocker status, Windows Defender
    state, and critical service status. Returns a structured integrity report.
.EXAMPLE
    Test-SystemIntegrity
#>
    [CmdletBinding()]
    param()

    $checks = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Result($Check, $Value, $Status, $Note) {
        $checks.Add([PSCustomObject]@{
            Check  = $Check
            Value  = $Value
            Status = $Status
            Note   = $Note
        })
    }

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Result 'Secure Boot' $sb $(if ($sb) {'Pass'} else {'Fail'}) 'Protects against bootkit attacks'
    } catch {
        Add-Result 'Secure Boot' 'Unavailable' 'Warning' 'Not supported or legacy BIOS mode'
    }

    # BitLocker
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $status = if ($bl.ProtectionStatus -eq 'On') {'Pass'} else {'Warning'}
        Add-Result 'BitLocker' $bl.ProtectionStatus $status "Volume: $env:SystemDrive"
    } catch {
        Add-Result 'BitLocker' 'Unavailable' 'Warning' 'Run as Administrator or BitLocker not installed'
    }

    # Windows Defender real-time protection
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $rtpStatus = if ($mpStatus.RealTimeProtectionEnabled) {'Pass'} else {'Fail'}
        Add-Result 'Defender RTP' $mpStatus.RealTimeProtectionEnabled $rtpStatus 'Real-time protection state'

        $sigAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
        $sigStatus = if ($sigAge.TotalDays -le 1) {'Pass'} elseif ($sigAge.TotalDays -le 7) {'Warning'} else {'Fail'}
        Add-Result 'Defender Signatures' "$([math]::Round($sigAge.TotalHours,1)) hours old" $sigStatus 'Signature currency'
    } catch {
        Add-Result 'Defender' 'Unavailable' 'Warning' 'Windows Defender not accessible'
    }

    # Critical services
    $criticalServices = @('wuauserv','WinDefend','EventLog','mpssvc')
    foreach ($svc in $criticalServices) {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            $status = if ($s.Status -eq 'Running') {'Pass'} else {'Warning'}
            Add-Result "Service: $svc" $s.Status $status $s.DisplayName
        } catch {
            Add-Result "Service: $svc" 'NotFound' 'Warning' 'Service not found'
        }
    }

    Write-Output $checks
}
