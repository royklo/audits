<#
.SYNOPSIS
    Generates a report of user password expiration dates in a Microsoft 365 tenant.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves user accounts in the tenant.
    It checks the tenant's password expiration policy and calculates the password expiration date for each user.
    The report includes details such as user display name, principal name, department, job title, last sign-in date, days since last sign-in, and days to password expiration.
    The report is displayed in a grid view and exported to a CSV file.

.NOTES
    Author: Roy Klooster
    Date: 03-10-2024
    Version: 1.1
    v1.0 - Initial release
    v1.1 - made some slight adjustments for auditing purposes

    Link to article: https://github.com/12Knocksinna/Office365itpros/blob/master/Report-ExpiringPasswords.PS1

.EXAMPLE
    .\Report-ExpiringPasswords.ps1
    This will generate a report of user password expiration dates for the current tenant.
#>


[datetime]$RunDate = Get-Date
[string]$ReportRunDate = Get-Date ($RunDate) -Format 'dd-MMM-yyyy HH:mm'
$Version = "1.0"

# Connect to Microsoft Graph - the first three scopes can be replaced by Directory.Read.All. The AuditLog.Read.All
# scope is needed to read the last sign-in date for each account
Connect-MgGraph -Scopes Domain.Read.All, User.Read.All, Organization.Read.All, AuditLog.Read.All -NoWelcome

# Get the organization name
$OrgName = (Get-MgOrganization).DisplayName

# Set the output file names
$ReportTitle = "Password Expiration Report"
$CSVOutputFile = "$pwd\$OrgName-Audit-PasswordExpirationReport.CSV"
$HtmlReportFile = "$pwd\$OrgName-Audit-PasswordExpirationReport.html"

# Check what the tenant password expiration policy is
[array]$Domains = Get-MgDomain
$DefaultDomain = $Domains | Where-Object { $_.IsDefault -eq $true }
$PasswordLifetime = $DefaultDomain.PasswordValidityPeriodInDays
If ($PasswordLifetime -eq 2147483647) {
    Write-Host "Password expiration is disabled for the tenant" -ForegroundColor Red
    $TenantPasswordExpirationDisabled = $true
    # adjust the value otherwise the date calculation will fail
    $PasswordLifetime = 20000
}
Else {
    Write-Host ("Password expiration is set to {0} days" -f $PasswordLifetime)
    $TenantPasswordExpirationDisabled = $false
}
 
# Find member accounts
Write-Host "Finding user accounts..."
#[Array]$Users = Get-MgUser -Filter "assignedLicenses/`$count ne 0 and userType eq 'Member'"  
[Array]$Users = Get-MgUser `
    -ConsistencyLevel eventual -CountVariable Records -All `
    -Property id, displayName, userPrincipalName, country, department, assignedlicenses, jobTitle, accountenabled, `
    licenseAssignmentStates, createdDateTime, signInActivity, companyName, passwordpolicies, lastPasswordChangeDateTime |  `
        Sort-Object DisplayName
 
# Extract Information about each user
$Report = [System.Collections.Generic.List[Object]]::new()
ForEach ($User in $Users) {
    $DisabledPasswordExpiry = $false
    Write-Host ("Checking {0}" -f $User.DisplayName)
    # Check if the user account password policy disables password expiration
    If ($User.PasswordPolicies -like "*DisablePasswordExpiration*") {
        $DisabledPasswordExpiry = $true
    }
    # Calculate the password expiry date
    [datetime]$PasswordExpiryDate = if ($null -ne $User.LastPasswordChangeDateTime) { $User.LastPasswordChangeDateTime.AddDays($PasswordLifetime) } else { [datetime]::MinValue }
    # Calculate the number of days to password expiration
    $DaystoExpiration = ($PasswordExpiryDate - (Get-Date)).Days
    $DaysSinceLastSignIn = if ($null -ne $User.SignInActivity.LastSignInDateTime) { ((Get-Date) - $User.SignInActivity.LastSignInDateTime).Days } else { [int]::MaxValue }
    
    $ReportLine = [PSCustomObject][Ordered]@{
        UserId                            = $User.Id
        UserDisplayName                   = $User.DisplayName
        UserPrincipalName                 = $User.UserPrincipalName
        Department                        = $User.Department
        'Job title'                       = $User.JobTitle
        'Last sign in'                    = if ($null -ne $User.SignInActivity.LastSignInDateTime) { Get-Date ($User.SignInActivity.LastSignInDateTime) -Format 'dd-MMM-yyyy HH:mm:ss' } else { "" }
        'Days since sign in'              = $DaysSinceLastSignIn
        'Password last changed'           = Get-Date ($User.LastPasswordChangeDateTime) -Format 'dd-MMM-yyyy HH:mm:ss'
        'Days since last password change' = if ($null -ne $User.LastPasswordChangeDateTime) { ((Get-Date) - $User.LastPasswordChangeDateTime).Days } else { "" }
        #PasswordExpiryDate                 = Get-Date ($PasswordExpiryDate) -Format 'dd-MMM-yyyy HH:mm:ss'
        DaysToExpiration                  = $DaystoExpiration
        #'Account Password Expiry Disabled' = $DisabledPasswordExpiry
        'Account enabled'                 = $User.AccountEnabled
    }
    $Report.Add($ReportLine)
}

$Report | Out-GridView -Title "Password Expiration Report"
$Report | Export-Csv -Path $CSVOutputFile -NoTypeInformation -Encoding UTF8

# Calculations
# Average number of days since last sign-in
$AverageSignInDays = $Report | Measure-Object -Property 'Days Since Sign in' -Average | Select-Object -Property Average
# Average number of days to password expiration
$AverageDaystoExpiration = $Report | Measure-Object -Property 'DaystoExpiration' -Average | Select-Object -Property Average
# Number of accounts with passwords that never expire
$AccountsNoPasswordExpiration = $Report | Where-Object { $_.'Account Password Expiry Disabled' -eq $true } | Measure-Object | Select-Object -Property Count

# Create the HTML report
$HtmlHead = "<html>
	   <style>
	   BODY{font-family: Arial; font-size: 10pt;}
	   H1{font-size: 28px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
	   H2{font-size: 20px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
	   H3{font-size: 16px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
	   TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
	   TH{border: 1px solid #969595; background: #dddddd; padding: 5px; color: #000000;}
	   TD{border: 1px solid #969595; padding: 5px; }
	   </style>
	   <body>
           <div align=center>
           <p><h1>" + $ReportTitle + "</h1></p>
           <p><h2><b>For the " + $Orgname + " tenant</b></h2></p>
           <p><h3>Generated: " + $ReportRunDate + "</h3></p></div>"

$HtmlBody = $Report | ConvertTo-Html -Fragment
$HtmlTail = ("<p><p><p>Report created for <b>{0}</b> on {1} <p>" -f $OrgName, $ReportRunDate)
$HtmlTail = $HtmlTail +
"<p>-----------------------------------------------------------------------------------------------------------------------------</p>" +  
"<p>Number of Entra ID accounts processed:           " + $Report.Count + "</p>" +
"<p>Average days since accounts last signed-in:      " + ("{0:n2}" -f $AverageSignInDays.average) + "</p>" +
"<p>Average days to password expiration:             " + ("{0:n2}" -f $AverageDaystoExpiration.average) + "</p>" +
"<p>Accounts with profiles for passwords not to expire: " + $AccountsNoPasswordExpiration.count + "</p>" +
"<p>Tenant password expiration policy set to not expire: " + $TenantPasswordExpirationDisabled + "</p>" +
"<p>Tenant password expiration period (days):            " + $PasswordLifetime + "</p>" +
"<p>-----------------------------------------------------------------------------------------------------------------------------</p>"

$HtmlTail = $HtmlTail + "<p><b>" + $ReportTitle + "</b> " + $Version + "</p>"	

$HtmlReport = $Htmlhead + $HtmlBody + $Htmltail
$HtmlReport | Out-File $HtmlReportFile -Encoding UTF8

Write-Host ("Complete. CSV file available in {0} and HTML report in {1}" -f $CSVOutputFile, $HtmlReportFile)

# An example script used to illustrate a concept. More information about the topic can be found in the Office 365 for IT Pros eBook https://gum.co/O365IT/
# and/or a relevant article on https://office365itpros.com or https://www.practical365.com. See our post about the Office 365 for IT Pros repository # https://office365itpros.com/office-365-github-repository/ for information about the scripts we write.

# Do not use our scripts in production until you are satisfied that the code meets the need of your organization. Never run any code downloaded from the Internet without
# first validating the code in a non-production environment.