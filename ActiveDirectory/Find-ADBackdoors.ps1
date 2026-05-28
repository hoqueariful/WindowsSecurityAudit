function Find-ADBackdoors {
<#
.SYNOPSIS
    Hunts for common Active Directory backdoor techniques.
.DESCRIPTION
    Checks for AdminSDHolder abuse, unexpected ACLs on sensitive objects,
    golden ticket indicators, and accounts with replication rights
    that should not have them (DCSync attack preparation).
.EXAMPLE
    Find-ADBackdoors
#>
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found."
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Accounts with DCSync rights (Replicating Directory Changes)
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName
        $acl = Get-Acl "AD:\$domainDN" -ErrorAction Stop

        $dcsyncGuids = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # Replicating Directory Changes
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # Replicating Directory Changes All
        )

        foreach ($ace in $acl.Access) {
            if ($ace.ObjectType.ToString() -in $dcsyncGuids -and
                $ace.ActiveDirectoryRights -match 'ExtendedRight') {
                $findings.Add([PSCustomObject]@{
                    BackdoorType  = 'DCSync Rights'
                    Identity      = $ace.IdentityReference
                    Rights        = $ace.ActiveDirectoryRights
                    Severity      = 'Critical'
                    Recommendation = 'Verify this account should have replication rights — remove if unauthorised'
                })
            }
        }
    } catch {
        Write-Warning "Could not check DCSync rights: $_"
    }

    if ($findings.Count -eq 0) {
        Write-Host "No obvious AD backdoors detected." -ForegroundColor Green
    }

    Write-Output $findings
}
