function Enable-AuditPolicies {
<#
.SYNOPSIS
    Enables recommended Windows audit policies for security monitoring.
.DESCRIPTION
    Configures Windows Advanced Audit Policy settings to capture events
    required for threat detection, incident response, and compliance.
    Based on CIS Benchmark and NSA guidance recommendations.
.PARAMETER WhatIf
    Preview which audit policies would be changed without applying them.
.EXAMPLE
    Enable-AuditPolicies
.EXAMPLE
    Enable-AuditPolicies -WhatIf
#>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $policies = @(
        @{ Category='Account Logon';         Subcategory='Credential Validation';         Setting='Success,Failure' }
        @{ Category='Account Management';    Subcategory='User Account Management';        Setting='Success,Failure' }
        @{ Category='Account Management';    Subcategory='Security Group Management';      Setting='Success,Failure' }
        @{ Category='Detailed Tracking';     Subcategory='Process Creation';              Setting='Success' }
        @{ Category='Logon/Logoff';          Subcategory='Logon';                         Setting='Success,Failure' }
        @{ Category='Logon/Logoff';          Subcategory='Logoff';                        Setting='Success' }
        @{ Category='Logon/Logoff';          Subcategory='Special Logon';                 Setting='Success' }
        @{ Category='Object Access';         Subcategory='Removable Storage';             Setting='Success,Failure' }
        @{ Category='Policy Change';         Subcategory='Audit Policy Change';           Setting='Success,Failure' }
        @{ Category='Policy Change';         Subcategory='Authentication Policy Change';  Setting='Success' }
        @{ Category='Privilege Use';         Subcategory='Sensitive Privilege Use';       Setting='Success,Failure' }
        @{ Category='System';                Subcategory='Security State Change';         Setting='Success,Failure' }
        @{ Category='System';                Subcategory='Security System Extension';     Setting='Success,Failure' }
        @{ Category='System';                Subcategory='System Integrity';              Setting='Success,Failure' }
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($policy in $policies) {
        $cmd = "auditpol /set /subcategory:`"$($policy.Subcategory)`" /$($policy.Setting.ToLower().Replace(',','/ '))"

        if ($PSCmdlet.ShouldProcess($policy.Subcategory, "Set audit: $($policy.Setting)")) {
            try {
                $output = & auditpol /set /subcategory:"$($policy.Subcategory)" `
                    /success:$(if ($policy.Setting -match 'Success') {'enable'} else {'disable'}) `
                    /failure:$(if ($policy.Setting -match 'Failure') {'enable'} else {'disable'}) 2>&1

                $status = if ($LASTEXITCODE -eq 0) {'Applied'} else {'Failed'}
                $results.Add([PSCustomObject]@{
                    Category    = $policy.Category
                    Subcategory = $policy.Subcategory
                    Setting     = $policy.Setting
                    Status      = $status
                })
            } catch {
                $results.Add([PSCustomObject]@{
                    Category    = $policy.Category
                    Subcategory = $policy.Subcategory
                    Setting     = $policy.Setting
                    Status      = "Error: $_"
                })
            }
        } else {
            $results.Add([PSCustomObject]@{
                Category    = $policy.Category
                Subcategory = $policy.Subcategory
                Setting     = $policy.Setting
                Status      = 'WhatIf — would apply'
            })
        }
    }

    Write-Host "`nAudit Policy Configuration Results:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize

    Write-Output $results
}
