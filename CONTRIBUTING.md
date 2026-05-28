# Contributing to WindowsSecurityAudit

Thank you for your interest in contributing!

## How to Contribute

### Implement a Stub Function
Several functions are marked as stub implementations. Pick any from the list below
and submit a pull request with a full working implementation:

- Analysis module: Get-EventLogAnalysis, Get-FileSystemAnalysis, Get-MemoryAnalysis, Get-RegistryAnalysis
- Forensics module: Export-MemoryDump, Get-ArtifactCollection, Get-ExecutionArtifacts, Get-USBHistory, New-ForensicTimeline
- ThreatHunting module: Find-APTIndicators, Find-DataExfiltration, Find-LateralMovement, Find-LivingOffLand, Get-MITREAttackMapping
- Response module: Invoke-ForensicCollection, Invoke-IncidentResponse

### Standards for Contributions

1. Every function must have a full comment-based help block (.SYNOPSIS, .DESCRIPTION, .EXAMPLE)
2. Use [CmdletBinding()] and Write-Verbose for debug output
3. Wrap external calls in try/catch with meaningful error messages
4. Return structured PSCustomObject output — not raw strings
5. Never hard-code paths or credentials
6. Test on both PowerShell 5.1 and PowerShell 7+

### Pull Request Process

1. Fork the repository
2. Create a branch named feature/FunctionName
3. Add your function to the correct module folder
4. Verify Test-Module.ps1 still shows 58 functions
5. Submit a pull request with a description of what the function does

## Reporting Issues

Open a GitHub Issue with:
- PowerShell version (PSVersionTable.PSVersion)
- Windows version
- The exact error message
- Steps to reproduce
