connect-mggraph -scope "Organization.Read.All, AuditLog.Read.All"

# Tenant name
$tenantname = (get-mgorganization).displayname

# Export path
$ExportPath = "$pwd\$tenantname-PIMauditsLogs.csv"

# Get PIM audits
$PIMaudits = Get-MgAuditLogDirectoryAudit -Filter "loggedByservice eq 'PIM'"

$results = @()
foreach ($PIMaudit in $PIMaudits) {
    $Initiatedby = ($PIMaudit.TargetResources | Where-Object {$_.type -eq "user"}).userprincipalname
    $role = ($PIMaudit.TargetResources | Where-Object {$_.Type -eq "Role"}).DisplayName
    $Reason = $PIMaudit.resultreason
    $starttime = $PIMaudit.AdditionalDetails | Where-Object {$_.key -eq "StartTime"} | Select-Object -ExpandProperty value | get-date -Format 'dd/MM/yyyy hh:mm:ss tt'
    $endtime = $PIMaudit.AdditionalDetails | Where-Object {$_.key -eq "EndTime"} | Select-Object -ExpandProperty value | get-date -Format 'dd/MM/yyyy hh:mm:ss tt'

    $results += [PSCustomObject]@{
        "id"    = $PIMaudit.Id
        "DataTime" = $PIMaudit.ActivityDateTime
        "Start Time" = $starttime
        "End Time" = $endtime
        "InitiatedBy" = $Initiatedby
        "Role" = $role
        "Operation" = $PIMaudit.ActivityDisplayName
        "Result" = $Reason
        #"TargetResources" = $PIMaudit.TargetResources
    }
}

$uniqueResults = $results | Select-Object -Property * -Unique
$uniqueResults | Export-Csv -Path $ExportPath -NoTypeInformation -encoding UTF8