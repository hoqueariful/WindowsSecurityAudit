#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Security Audit Module — Loader
.DESCRIPTION
    Auto-discovers and dot-sources every .ps1 function file in all
    sub-directories except Private (which is sourced separately).
    Author : Ariful Hoque
    Version: 1.0.0
    License: MIT
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Load Private helpers first ──────────────────────────────────────────────
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' -Recurse |
        ForEach-Object { . $_.FullName }
}

# ── Load all public functions ────────────────────────────────────────────────
$publicFolders = @(
    'ActiveDirectory','Analysis','CloudSecurity','Compliance','Core',
    'Detection','Enterprise','Forensics','Hardening','Reporting',
    'Response','ThreatHunting','Vulnerability','WindowsDefender'
)

foreach ($folder in $publicFolders) {
    $folderPath = Join-Path $PSScriptRoot $folder
    if (Test-Path $folderPath) {
        Get-ChildItem -Path $folderPath -Filter '*.ps1' -Recurse |
            ForEach-Object { . $_.FullName }
    }
}

# ── Module banner ────────────────────────────────────────────────────────────
$functionCount = (Get-Command -Module WindowsSecurityAudit -ErrorAction SilentlyContinue).Count
Write-Host ""
Write-Host "  Windows Security Audit Module v1.0.0" -ForegroundColor Cyan
Write-Host "  $functionCount functions loaded across 14 modules" -ForegroundColor Green
Write-Host "  Run Get-Command -Module WindowsSecurityAudit to list all functions" -ForegroundColor Gray
Write-Host ""
