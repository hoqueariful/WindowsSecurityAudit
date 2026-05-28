<#
.SYNOPSIS
    Tests that all 58 functions in WindowsSecurityAudit are loadable.
.DESCRIPTION
    Imports the module and verifies the expected function count.
    Run this after any changes to validate the module loads cleanly.
.EXAMPLE
    .\Test-Module.ps1
#>

$modulePath = Join-Path $PSScriptRoot 'WindowsSecurityAudit.psd1'

Write-Host "`nImporting WindowsSecurityAudit module..." -ForegroundColor Cyan

Import-Module $modulePath -Force

$functions = Get-Command -Module WindowsSecurityAudit
$count     = $functions.Count

Write-Host "Functions loaded: $count" -ForegroundColor $(if ($count -ge 58) {'Green'} else {'Yellow'})

if ($count -lt 58) {
    Write-Warning "Expected 58 functions, got $count. Check for missing .ps1 files."
}

Write-Host "`nFunction list:" -ForegroundColor Gray
$functions | Sort-Object Name | Format-Table Name, Module -AutoSize
