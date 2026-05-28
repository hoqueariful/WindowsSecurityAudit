# Changelog

All notable changes to WindowsSecurityAudit are documented here.

## [1.0.0] — 2025-06-01

### Added
- 58 functions across 14 security modules
- Full implementations: Core, Detection, ActiveDirectory, Hardening, Compliance, Reporting, Vulnerability
- HTML security dashboard via New-SecurityDashboard
- CIS Benchmark Level 1 assessment via Test-CISBenchmark
- NIST SP 800-53 compliance checks via Test-NISTCompliance
- Persistence mechanism hunting via Find-PersistenceMechanisms
- Suspicious process detection via Find-SuspiciousProcesses
- Authentication anomaly detection via Find-SuspiciousAuthentication
- Network anomaly detection via Find-NetworkAnomalies
- PowerShell security hardening via Enable-PowerShellSecurity
- Audit policy configuration via Enable-AuditPolicies
- Security baseline application via Set-SecurityBaseline
- AD privileged account enumeration via Get-ADPrivilegedAccounts
- AD password policy assessment via Get-ADPasswordPolicy
- Stale AD object detection via Find-StaleADObjects
- AD backdoor hunting via Find-ADBackdoors
- Kerberoast/AS-REP vulnerability checks via Find-ADVulnerabilities

### Planned for v1.1.0
- Full implementation of Analysis, Forensics, ThreatHunting, Response, CloudSecurity modules
- Pester test suite
- PowerShell Gallery publication
