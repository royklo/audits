<#
.SYNOPSIS
    Generates a report of user group memberships in a Microsoft 365 tenant.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves all users in the tenant, and then fetches their group memberships.
    It compiles this information into a report, which includes the group name, group type, membership rule, and user principal name.
    The report is sorted by group name and exported to a CSV file named "<TenantName>-Audit-UserGroupMemberships.csv".

.NOTES
    Author: Roy Klooster
    Date: 03-10-2024
    Version: 1.0

.EXAMPLE
    .\Report-UserGroupMemberships.ps1
    This will generate a CSV report of user group memberships for the current tenant.

#>

# Connect to Microsoft Graph
Connect-MgGraph

# Get organization information
$tenantname = (Get-MgOrganization).DisplayName

# Get all users in the tenant
$Users = Get-MgUser -All

$Report = @()
foreach ($user in $Users) {
    $GroupMemberships = Get-MgUserMemberOf -UserId $user.id 
    

    foreach ($group in $GroupMemberships) {
        if (-not $group.AdditionalProperties.groupTypes) {
            $group.AdditionalProperties.groupTypes = "StaticMembership"
        }

        $Report += [PSCustomObject]@{
            GroupName         = $group.AdditionalProperties.displayName
            GroupType         = $group.AdditionalProperties.groupTypes -join ', '
            MembershipRule    = $group.AdditionalProperties.membershipRule
            #DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
        }
    }
}

$Report = $Report | Sort-Object GroupName 

$path = "$($pwd)\$tenantname-Audit-UserGroupMemberships.csv"
$Report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 

Disconnect-MgGraph

