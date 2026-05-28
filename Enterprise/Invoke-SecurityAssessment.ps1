function Invoke-SecurityAssessment {
<#
.SYNOPSIS
    Runs a complete end-to-end security assessment on the local Windows system.
.DESCRIPTION
    Orchestrates all available local security checks and produces a consolidated
    HTML and JSON report. This is the primary entry-point for a full system assessment.
.PARAMETER OutputPath
    Path to save the assessment report. Default: Documents folder.
.PARAMETER Scope
    Assessment scope: Full, Quick, or Compliance. Default: Full.
.EXAMPLE
    Invoke-SecurityAssessment
    Invoke-SecurityAssessment -Scope Quick -OutputPath "C:\Reports"
#>
    [CmdletBinding()]
    param(
        [string]$OutputPath = "$env:USERPROFILE\Documents",
        [ValidateSet('Full','Quick','Compliance')]
        [string]$Scope = 'Full'
    )

    $StartTime = Get-Date
    $Report    = [ordered]@{
        AssessmentId  = [System.Guid]::NewGuid().ToString()
        StartTime     = $StartTime
        Hostname      = $env:COMPUTERNAME
        AssessedBy    = $env:USERNAME
        Scope         = $Scope
        Findings      = [ordered]@{}
    }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Windows Security Assessment Engine     ║" -ForegroundColor Cyan
    Write-Host "  ║   Scope: $($Scope.PadRight(32))║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $Steps = switch ($Scope) {
        'Quick'      { @('SystemInfo','SystemIntegrity','SuspiciousProcesses','NetworkAnomalies') }
        'Compliance' { @('CISBenchmark','NISTCompliance','PCI-DSS') }
        default      { @('SystemInfo','SystemIntegrity','PersistenceMechanisms','SuspiciousProcesses',
                         'SuspiciousAuthentication','NetworkAnomalies','VulnerabilityAssessment',
                         'SecurityMisconfigurations','RegistryAnalysis','CISBenchmark') }
    }

    $StepNum = 0
    foreach ($Step in $Steps) {
        $StepNum++
        Write-Host "  [$StepNum/$($Steps.Count)] Running: $Step..." -ForegroundColor Gray -NoNewline

        $StepResult = try {
            switch ($Step) {
                'SystemInfo'             { Get-SystemInfo }
                'SystemIntegrity'        { Test-SystemIntegrity }
                'PersistenceMechanisms'  { Find-PersistenceMechanisms }
                'SuspiciousProcesses'    { Find-SuspiciousProcesses }
                'SuspiciousAuthentication' { Find-SuspiciousAuthentication }
                'NetworkAnomalies'       { Find-NetworkAnomalies }
                'VulnerabilityAssessment'{ Get-VulnerabilityAssessment }
                'SecurityMisconfigurations' { Get-SecurityMisconfigurations }
                'RegistryAnalysis'       { Get-RegistryAnalysis }
                'CISBenchmark'           { Test-CISBenchmark }
                'NISTCompliance'         { Test-NISTCompliance }
                'PCI-DSS'                { Test-PCI-DSS }
            }
        } catch { "Error: $_" }

        $Report.Findings[$Step] = $StepResult
        Write-Host " Done ($((($StepResult | Measure-Object).Count)) items)" -ForegroundColor Green
    }

    $Report.EndTime  = Get-Date
    $Report.Duration = ($Report.EndTime - $StartTime).ToString('mm\:ss')

    # Save JSON report
    $Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $JsonPath   = Join-Path $OutputPath "SecurityAssessment_$($env:COMPUTERNAME)_$Timestamp.json"
    $Report | ConvertTo-Json -Depth 8 | Out-File $JsonPath -Encoding UTF8

    Write-Host ""
    Write-Host "  Assessment complete in $($Report.Duration)" -ForegroundColor Green
    Write-Host "  Report saved: $JsonPath" -ForegroundColor Cyan

    return [PSCustomObject]$Report
}
