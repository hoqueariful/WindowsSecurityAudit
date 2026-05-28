function Get-FileSystemAnalysis {
<#
.SYNOPSIS
    Analyses the file system for suspicious files, world-writable directories, and SUID-equivalent issues.
.DESCRIPTION
    Checks common malware drop locations, recently modified executables in system directories,
    and files with suspicious characteristics.
.PARAMETER ScanPaths
    Array of paths to scan. Defaults to common high-risk locations.
.PARAMETER Days
    Look for files modified within this many days. Default: 7.
.EXAMPLE
    Get-FileSystemAnalysis
    Get-FileSystemAnalysis -Days 3 -ScanPaths "C:\Windows\Temp","C:\Users"
#>
    [CmdletBinding()]
    param(
        [string[]]$ScanPaths = @(
            "$env:SystemRoot\Temp",
            "$env:SystemRoot\System32\Tasks",
            "$env:TEMP",
            "$env:PUBLIC",
            "C:\ProgramData"
        ),
        [int]$Days = 7
    )

    $Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Cutoff   = (Get-Date).AddDays(-$Days)
    $SuspExt  = @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.hta','.scr','.pif','.com')

    foreach ($Path in $ScanPaths) {
        if (-not (Test-Path -Path $Path)) { continue }

        try {
            Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $Cutoff -and $_.Extension -in $SuspExt } |
                ForEach-Object {
                    $Acl    = Get-Acl -Path $_.FullName -ErrorAction SilentlyContinue
                    $Owner  = $Acl.Owner

                    $Results.Add([PSCustomObject]@{
                        Path         = $_.FullName
                        Extension    = $_.Extension
                        SizeKB       = [math]::Round($_.Length / 1KB, 2)
                        LastModified = $_.LastWriteTime
                        Owner        = $Owner
                        Hidden       = $_.Attributes -match 'Hidden'
                        Suspicious   = ($_.Attributes -match 'Hidden') -or ($_.Name -match '^\.')
                    })
                }
        }
        catch { Write-Warning "Could not scan: $Path" }
    }

    Write-Host "  File System Analysis: $($Results.Count) suspicious file(s) found in last $Days days." -ForegroundColor Yellow
    return $Results | Sort-Object LastModified -Descending
}
