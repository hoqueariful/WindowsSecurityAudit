function Get-SystemInfo {
<#
.SYNOPSIS
    Collects comprehensive system information for security auditing.
.DESCRIPTION
    Returns OS version, hardware details, domain membership, installed
    hotfixes, running services, and current user context in a structured object.
.EXAMPLE
    Get-SystemInfo
.EXAMPLE
    Get-SystemInfo | Export-Csv -Path C:\Reports\SystemInfo.csv -NoTypeInformation
#>
    [CmdletBinding()]
    param()

    Write-Verbose "Collecting system information..."

    $os     = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs     = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios   = Get-CimInstance -ClassName Win32_BIOS
    $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5

    [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        Domain             = $cs.Domain
        OSName             = $os.Caption
        OSVersion          = $os.Version
        OSBuildNumber      = $os.BuildNumber
        Architecture       = $os.OSArchitecture
        LastBootTime       = $os.LastBootUpTime
        InstallDate        = $os.InstallDate
        TotalMemoryGB      = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        BIOSVersion        = $bios.SMBIOSBIOSVersion
        LoggedOnUser       = "$env:USERDOMAIN\$env:USERNAME"
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        Last5Hotfixes      = ($hotfix | Select-Object -ExpandProperty HotFixID) -join ', '
        CollectedAt        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}
