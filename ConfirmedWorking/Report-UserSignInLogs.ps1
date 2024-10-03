# Connect to Graph API
Connect-MgGraph

# Get Tenant Display Name
$tenantname = (Get-MgOrganization).DisplayName

# Get all users
$Users = Get-MgUser -All -Property id, userprincipalname, signinactivity, accountEnabled

$Report = @()
$count = 0
foreach ($User in $Users) {
    $count++
    if ($User.SignInActivity.LastSignInDateTime) {
        try {
            $datetime = $user.SignInActivity.LastSignInDateTime -as [datetime]
        }
        catch {
            $datetime = $null
        }
        $formattedDateTime = $datetime.ToString("dd/MM/yyyy HH:mm")
    }
    else {
        $formattedDateTime = "Never Signed In"
    }

    Write-Output "($count/$($Users.Count)) - User: $($User.UserPrincipalName) - Last Sign In: $formattedDateTime"

    $Report += [PSCustomObject]@{
        UserPrincipalName  = $User.UserPrincipalName
        Status             = $User.AccountEnabled
        LastSignIn         = $formattedDateTime
        DaysSinceLastLogin = (New-TimeSpan -Start $datetime -End (Get-Date)).Days
    }
}

$Report = $Report | Sort-Object UserPrincipalName

$path = "$($pwd)\$($tenantname)-Audit-UserLastSignInLog.csv"
$Report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 

#Disconnect-MgGraph
