function Find-StaleADObjects {
<#
.SYNOPSIS
    Finds stale user accounts and computer objects in Active Directory.
.DESCRIPTION
    Returns user accounts inactive for more than a specified number of days
    and computer accounts that have not authenticated recently.
    Stale accounts are a primary attack surface for lateral movement.
.PARAMETER DaysInactive
    Number of days without logon to consider an object stale. Default is 90.
.EXAMPLE
    Find-StaleADObjects
.EXAMPLE
    Find-StaleADObjects -DaysInactive 60
#>
    [CmdletBinding()]
    param(
        [int]$DaysInactive = 90
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    $cutoff = (Get-Date).AddDays(-$DaysInactive)

    Write-Host "Searching for objects inactive since: $($cutoff.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan

    # Stale Users
    $staleUsers = Get-ADUser -Filter {
        LastLogonDate -lt $cutoff -and Enabled -eq $true
    } -Properties LastLogonDate, WhenCreated, Description |
    Select-Object SamAccountName, Name, LastLogonDate, WhenCreated, Description,
        @{N='ObjectType';E={'User'}},
        @{N='InactiveDays';E={ ((Get-Date) - $_.LastLogonDate).Days }}

    # Stale Computers
    $staleComputers = Get-ADComputer -Filter {
        LastLogonDate -lt $cutoff -and Enabled -eq $true
    } -Properties LastLogonDate, OperatingSystem |
    Select-Object Name, LastLogonDate, OperatingSystem,
        @{N='ObjectType';E={'Computer'}},
        @{N='InactiveDays';E={ ((Get-Date) - $_.LastLogonDate).Days }}

    $combined = @($staleUsers) + @($staleComputers)

    Write-Host "Found $($staleUsers.Count) stale users and $($staleComputers.Count) stale computers." -ForegroundColor Yellow

    Write-Output $combined | Sort-Object InactiveDays -Descending
}
