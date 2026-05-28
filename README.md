# Windows Security Audit Module

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=for-the-badge&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows)
![Functions](https://img.shields.io/badge/Functions-58-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

Enterprise-grade Windows security auditing, threat detection, compliance validation,
and incident response toolkit built entirely on native PowerShell with zero external
dependencies.

---

## What This Module Does

Most organisations run 10 to 15 different security tools, each with its own interface,
license cost, and learning curve. This module consolidates the most critical security
functions into a single cohesive PowerShell toolkit that any administrator or analyst
can run immediately on any Windows system with no installation of agents or third-party
software.

---

## Quick Start

```powershell
# Install from PowerShell Gallery
Install-Module -Name WindowsSecurityAudit -Scope CurrentUser -Force
Import-Module WindowsSecurityAudit

# Or load directly from source
Import-Module .\WindowsSecurityAudit.psd1

# Verify all 58 functions loaded
(Get-Command -Module WindowsSecurityAudit).Count

# Generate an HTML security dashboard
New-SecurityDashboard

# Run a full security baseline check
Get-SecurityBaseline

# Hunt for persistence mechanisms
Find-PersistenceMechanisms

# Check CIS Benchmark compliance
Test-CISBenchmark

# Scan for suspicious processes
Find-SuspiciousProcesses
```

---

## Module Structure

```
WindowsSecurityAudit/
│
├── WindowsSecurityAudit.psd1          Module manifest
├── WindowsSecurityAudit.psm1          Module loader
├── CreateProjectFolderStructure.ps1   Setup script
├── Test-Module.ps1                    Validation script
│
├── ActiveDirectory/                   6 functions
│   ├── Find-ADBackdoors.ps1
│   ├── Find-ADVulnerabilities.ps1
│   ├── Find-StaleADObjects.ps1
│   ├── Get-ADPasswordPolicy.ps1
│   ├── Get-ADPrivilegedAccounts.ps1
│   └── Test-ADSecurityPosture.ps1
│
├── Analysis/                          4 functions
├── CloudSecurity/                     3 functions
├── Compliance/                        5 functions
│   ├── Test-CISBenchmark.ps1
│   └── Test-NISTCompliance.ps1
│
├── Core/                              4 functions
│   ├── Get-EventIdDescription.ps1
│   ├── Get-SecurityBaseline.ps1
│   ├── Get-SystemInfo.ps1
│   └── Test-SystemIntegrity.ps1
│
├── Detection/                         4 functions
│   ├── Find-NetworkAnomalies.ps1
│   ├── Find-PersistenceMechanisms.ps1
│   ├── Find-SuspiciousAuthentication.ps1
│   └── Find-SuspiciousProcesses.ps1
│
├── Enterprise/                        3 functions
├── Forensics/                         5 functions
├── Hardening/                         3 functions
│   ├── Enable-AuditPolicies.ps1
│   ├── Enable-PowerShellSecurity.ps1
│   └── Set-SecurityBaseline.ps1
│
├── Reporting/                         3 functions
│   └── New-SecurityDashboard.ps1
│
├── Response/                          3 functions
├── ThreatHunting/                     6 functions
├── Vulnerability/                     6 functions
│   ├── Get-ExposedServices.ps1
│   ├── Get-SecurityMisconfigurations.ps1
│   ├── Get-VulnerabilityAssessment.ps1
│   └── Test-PatchCompliance.ps1
│
└── WindowsDefender/                   3 functions
```

---

## Function Reference

### Core Module

| Function | Description |
|---|---|
| Get-SystemInfo | Full system snapshot for audit baseline |
| Get-SecurityBaseline | Evaluates firewall, SMBv1, UAC, NTLMv2, RDP NLA |
| Get-EventIdDescription | Maps Windows Event IDs to analyst descriptions |
| Test-SystemIntegrity | Checks Secure Boot, BitLocker, Defender, services |

### Detection Module

| Function | Description |
|---|---|
| Find-SuspiciousProcesses | Detects processes in unusual paths, LOLBins, encoded PS |
| Find-SuspiciousAuthentication | Brute force, password spray, off-hours logon detection |
| Find-PersistenceMechanisms | Run keys, scheduled tasks, WMI, startup folder hunting |
| Find-NetworkAnomalies | Suspicious ports, unusual outbound connections |

### Active Directory Module

| Function | Description |
|---|---|
| Get-ADPrivilegedAccounts | All members of privileged AD groups with risk flags |
| Get-ADPasswordPolicy | Password policy assessment against CIS and NIST |
| Find-StaleADObjects | Users and computers inactive 90+ days |
| Find-ADVulnerabilities | Kerberoastable and AS-REP Roastable accounts |
| Find-ADBackdoors | DCSync rights, unauthorised ACLs |
| Test-ADSecurityPosture | Full AD security posture in one command |

### Compliance Module

| Function | Description |
|---|---|
| Test-CISBenchmark | CIS Level 1 controls for Windows |
| Test-NISTCompliance | NIST SP 800-53 control family mapping |
| Test-PCI-DSS | PCI-DSS relevant controls (stub — v1.1.0) |

### Hardening Module

| Function | Description |
|---|---|
| Enable-AuditPolicies | Applies 14 recommended audit policy settings |
| Enable-PowerShellSecurity | Script block logging, module logging, transcription |
| Set-SecurityBaseline | LLMNR, NTLMv2, SMB signing, guest account lockdown |

### Vulnerability Module

| Function | Description |
|---|---|
| Get-VulnerabilityAssessment | Full local vulnerability scan |
| Test-PatchCompliance | Windows Update currency and hotfix count |
| Get-ExposedServices | Listening services on risky ports |
| Get-SecurityMisconfigurations | AutoRun, LLMNR, NetBIOS, guest account |

### Reporting Module

| Function | Description |
|---|---|
| New-SecurityDashboard | Generates styled HTML report with all key findings |
| Get-SecurityMetrics | Collects numerical security KPIs (stub — v1.1.0) |
| New-ExecutiveReport | Management-level summary report (stub — v1.1.0) |

---

## Requirements

```
Operating System   Windows 10 1809+  or  Windows Server 2016+
PowerShell         5.1 (Windows PowerShell) or 7+
Privileges         Local Administrator for most functions
                   Domain Administrator for AD module
RAM                4GB minimum  (8GB recommended for full scan)
Dependencies       None — native PowerShell only
```

Optional for specific modules:
- Active Directory PowerShell Module (RSAT) for AD functions
- Azure AD PowerShell for cloud security functions

---

## Examples

```powershell
# Full system audit in one line
Invoke-SecurityAssessment

# Find all privileged AD accounts with risky configurations
Get-ADPrivilegedAccounts | Where-Object RiskFlags -ne ''

# Check which Event IDs matter and why
4625, 4648, 4672, 4698, 1102 | ForEach-Object { Get-EventIdDescription $_ }

# Find authentication anomalies from last 48 hours
Find-SuspiciousAuthentication -Hours 48 -FailureThreshold 10

# Apply PowerShell hardening (preview first)
Enable-PowerShellSecurity -WhatIf
Enable-PowerShellSecurity

# Export CIS Benchmark results to CSV
Test-CISBenchmark | Export-Csv -Path .\CIS-Results.csv -NoTypeInformation

# Generate and auto-open HTML dashboard
$report = New-SecurityDashboard
Start-Process $report.ReportPath
```

---

## Security Notice

This module is designed for use by administrators and security professionals on
systems they own and are authorised to assess. Using these tools against systems
without explicit authorisation is illegal. Always obtain written authorisation
before running security assessments.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to implement stub functions,
submit pull requests, and report issues.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## Author

**Ariful Hoque**
Cybersecurity | Cloud Security | Windows Infrastructure

GitHub: [hoqueariful](https://github.com/hoqueariful)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
