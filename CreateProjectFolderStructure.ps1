<#
.SYNOPSIS
    Creates the WindowsSecurityAudit project folder structure.
.DESCRIPTION
    Run this script once to scaffold the project directories if you
    are setting up a development environment from scratch.
.EXAMPLE
    .\CreateProjectFolderStructure.ps1
#>

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$folders = @(
    'ActiveDirectory','Analysis','CloudSecurity','Compliance','Core',
    'Detection','Enterprise','Forensics','Hardening','Private',
    'Reporting','Response','Tests','ThreatHunting','Vulnerability','WindowsDefender'
)

foreach ($folder in $folders) {
    $path = Join-Path $root $folder
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
        Write-Host "Created: $folder" -ForegroundColor Green
    } else {
        Write-Host "Exists : $folder" -ForegroundColor Gray
    }
}

Write-Host "`nProject structure ready at: $root" -ForegroundColor Cyan
