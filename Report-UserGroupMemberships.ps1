# Connect to Microsoft Graph
# Connect-mggraph

# Get organization information
$tenantname = (Get-mgorganization).DisplayName
# Get all users in the tenant
#$Users = Get-MgUser -All -Property AssignedLicenses, LicenseAssignmentStates, DisplayName, UserPrincipalName | Select-Object DisplayName,UserPrincipalName, AssignedLicenses -ExpandProperty LicenseAssignmentStates

$Users = Get-mguser -all

$Report = @()
foreach ($user in $Users) {
    $GroupMemberships = Get-MgUserMemberOf -UserID $user.id 
    

    foreach ($group in $GroupMemberships) {
        if (-not $group.AdditionalProperties.groupTypes) {
            $group.AdditionalProperties.groupTypes = "StaticMembership"
        }

        $Report += [PSCustomObject]@{
            GroupName = $group.AdditionalProperties.displayName
            GroupType = $group.AdditionalProperties.groupTypes -join ', '
            MembershipRule = $group.AdditionalProperties.membershipRule
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
        }
    }
}

$Report | Sort-Object GroupName | ft -autosize



