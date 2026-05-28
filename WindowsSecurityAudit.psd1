@{
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Ariful Hoque'
    CompanyName       = 'Community'
    Copyright         = '(c) 2025 Ariful Hoque. MIT License.'
    Description       = 'Enterprise-grade Windows security auditing, threat detection, compliance validation, and incident response toolkit built entirely on native PowerShell with zero external dependencies.'
    PowerShellVersion = '5.1'
    RootModule        = 'WindowsSecurityAudit.psm1'

    FunctionsToExport = @(
        'Find-ADBackdoors','Find-ADVulnerabilities','Find-StaleADObjects',
        'Get-ADPasswordPolicy','Get-ADPrivilegedAccounts','Test-ADSecurityPosture',
        'Get-EventLogAnalysis','Get-FileSystemAnalysis','Get-MemoryAnalysis','Get-RegistryAnalysis',
        'Get-AzureADRiskySignIns','Get-CloudComplianceStatus','Test-M365SecurityPosture',
        'Export-ComplianceEvidence','Get-ComplianceReport','Test-CISBenchmark','Test-NISTCompliance','Test-PCI-DSS',
        'Get-EventIdDescription','Get-SecurityBaseline','Get-SystemInfo','Test-SystemIntegrity',
        'Find-NetworkAnomalies','Find-PersistenceMechanisms','Find-SuspiciousAuthentication','Find-SuspiciousProcesses',
        'Get-MultiSystemAudit','Invoke-EnterpriseSecurityScan','Invoke-SecurityAssessment',
        'Export-MemoryDump','Get-ArtifactCollection','Get-ExecutionArtifacts','Get-USBHistory','New-ForensicTimeline',
        'Enable-AuditPolicies','Enable-PowerShellSecurity','Set-SecurityBaseline',
        'Get-SecurityMetrics','New-ExecutiveReport','New-SecurityDashboard',
        'Export-SecurityReport','Invoke-ForensicCollection','Invoke-IncidentResponse',
        'Find-APTIndicators','Find-DataExfiltration','Find-LateralMovement','Find-LivingOffLand','Get-MITREAttackMapping','Get-ThreatIntelligence',
        'Find-EOLSoftware','Get-ExposedServices','Get-SecurityMisconfigurations','Get-VulnerabilityAssessment','Test-CertificateHealth','Test-PatchCompliance',
        'Get-DefenderStatus','Invoke-DefenderScan','Update-DefenderConfiguration'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('Security','Audit','Windows','Compliance','Forensics','ThreatHunting','ActiveDirectory','Hardening','NIST','CIS')
            LicenseUri   = 'https://github.com/hoqueariful/WindowsSecurityAudit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/hoqueariful/WindowsSecurityAudit'
            ReleaseNotes = 'Initial release v1.0.0'
        }
    }
}
