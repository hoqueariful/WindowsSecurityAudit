function Get-EventIdDescription {
<#
.SYNOPSIS
    Returns human-readable descriptions for common Windows Security Event IDs.
.DESCRIPTION
    Provides analyst-friendly descriptions, categories, and recommended
    actions for the most investigated Windows Security Event IDs.
.PARAMETER EventId
    The Windows Event ID to look up.
.EXAMPLE
    Get-EventIdDescription -EventId 4625
.EXAMPLE
    4624,4625,4672,4776 | ForEach-Object { Get-EventIdDescription -EventId $_ }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]$EventId
    )

    $catalog = @{
        4624 = @{ Category='Logon';        Severity='Info';    Description='Successful account logon';                                  Action='Baseline normal logon patterns' }
        4625 = @{ Category='Logon';        Severity='High';    Description='Failed account logon';                                      Action='Investigate repeated failures — possible brute force' }
        4634 = @{ Category='Logon';        Severity='Info';    Description='Account logoff';                                            Action='Correlate with 4624 for session duration' }
        4648 = @{ Category='Logon';        Severity='Medium';  Description='Logon using explicit credentials (runas)';                  Action='Verify legitimacy — common in lateral movement' }
        4672 = @{ Category='Privilege';    Severity='High';    Description='Special privileges assigned to new logon';                  Action='Monitor for unexpected admin-level access' }
        4688 = @{ Category='Process';      Severity='Medium';  Description='New process created';                                       Action='Enable command line logging for full visibility' }
        4698 = @{ Category='Scheduling';   Severity='High';    Description='Scheduled task created';                                    Action='Investigate — common persistence mechanism' }
        4702 = @{ Category='Scheduling';   Severity='High';    Description='Scheduled task updated';                                    Action='Check for task hijacking' }
        4720 = @{ Category='Account';      Severity='High';    Description='User account created';                                      Action='Verify authorised account creation' }
        4722 = @{ Category='Account';      Severity='Medium';  Description='User account enabled';                                      Action='Correlate with 4720 for new account activity' }
        4723 = @{ Category='Account';      Severity='Medium';  Description='Password change attempted';                                 Action='Correlate with failed logons' }
        4724 = @{ Category='Account';      Severity='High';    Description='Password reset attempted';                                  Action='Verify admin performing reset is authorised' }
        4728 = @{ Category='Group';        Severity='High';    Description='Member added to security-enabled global group';             Action='Verify group membership change is authorised' }
        4732 = @{ Category='Group';        Severity='High';    Description='Member added to security-enabled local group';              Action='Check for unauthorised local admin additions' }
        4756 = @{ Category='Group';        Severity='High';    Description='Member added to security-enabled universal group';          Action='Monitor in AD environments' }
        4768 = @{ Category='Kerberos';     Severity='Info';    Description='Kerberos TGT requested';                                   Action='Baseline — alert on unusual volume' }
        4769 = @{ Category='Kerberos';     Severity='Medium';  Description='Kerberos service ticket requested';                         Action='Watch for Kerberoasting (many requests in short time)' }
        4771 = @{ Category='Kerberos';     Severity='High';    Description='Kerberos pre-auth failed';                                  Action='Investigate — may indicate password spray' }
        4776 = @{ Category='NTLM';         Severity='Medium';  Description='NTLM credential validation attempted';                      Action='Alert if NTLMv1 in use' }
        4778 = @{ Category='Session';      Severity='Info';    Description='Remote desktop session reconnected';                        Action='Correlate with 4624 Type 10 logons' }
        4779 = @{ Category='Session';      Severity='Info';    Description='Remote desktop session disconnected';                       Action='Normal — audit for after-hours patterns' }
        7045 = @{ Category='Service';      Severity='High';    Description='New service installed';                                     Action='Investigate immediately — malware persistence vector' }
        4697 = @{ Category='Service';      Severity='High';    Description='Service installed in the system';                          Action='Alert on unexpected service installs' }
        1102 = @{ Category='Audit';        Severity='Critical';Description='Audit log cleared';                                        Action='Immediate investigation — anti-forensic indicator' }
        4657 = @{ Category='Registry';     Severity='Medium';  Description='Registry value modified';                                  Action='Monitor sensitive keys (Run, Services, LSA)' }
        4663 = @{ Category='FileSystem';   Severity='Low';     Description='Object access attempted';                                  Action='Enable only on sensitive folders to reduce noise' }
    }

    if ($catalog.ContainsKey($EventId)) {
        $entry = $catalog[$EventId]
        [PSCustomObject]@{
            EventId        = $EventId
            Category       = $entry.Category
            Severity       = $entry.Severity
            Description    = $entry.Description
            RecommendedAction = $entry.Action
        }
    } else {
        [PSCustomObject]@{
            EventId        = $EventId
            Category       = 'Unknown'
            Severity       = 'Unknown'
            Description    = "Event ID $EventId not in local catalog"
            RecommendedAction = 'Search Microsoft Event ID documentation'
        }
    }
}
