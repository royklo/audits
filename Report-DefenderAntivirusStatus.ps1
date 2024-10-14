# https://ourcloudnetwork.com/defender-for-endpoint-status-report-with-microsoft-graph-powershell/
# https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/AgentStatusReportBlade

#Define the output path
$date = (Get-Date -Format 'yyyy-MM-dd')
$OutputPath = "C:\temp\"
$OutputFile = "$($date)-AV-report.zip"
$OutputPath = $OutputPath + $OutputFile

$tenantname = (Get-MgOrganization).DisplayName

#Connect to Microsoft Graph
#Connect-MgGraph -Scopes DeviceManagementConfiguration.Read.All

#Define body of request, including the report name
$body = @'
{
  "filter": "",
  "format": "csv",
  "select": [
    "DeviceName",
    "DeviceState",
    "_ManagedBy",
    "AntiMalwareVersion",
    "CriticalFailure",
    "ProductStatus",
    "TamperProtectionEnabled",
    "IsVirtualMachine",
    "IsWDATPSenseRunning",
    "WDATPOnboardingState",
    "EngineVersion",
    "FullScanOverdue",
    "FullScanRequired",
    "LastFullScanDateTime",
    "LastQuickScanDateTime",
    "LastQuickScanSignatureVersion",
    "LastReportedDateTime",
    "MalwareProtectionEnabled",
    "NetworkInspectionSystemEnabled",
    "PendingFullScan",
    "PendingManualSteps",
    "PendingOfflineScan",
    "PendingReboot",
    "QuickScanOverdue",
    "RealTimeProtectionEnabled",
    "RebootRequired",
    "SignatureUpdateOverdue",
    "SignatureVersion",
    "UPN",
    "UserEmail",
    "UserName"
  ],
  "skip": 0,
  "top": 0,
  "search": "",
  "reportName": "DefenderAgents"
}
'@

#Initiate report processing
$response = Invoke-MgGraphRequest -Method POST -Uri "/beta/deviceManagement/reports/exportJobs" -Body $body

$uri = "/beta/deviceManagement/reports/exportJobs('" + "$($response.id)" + "')"

#Loop until report processing is complete
Do {
    $response2 = Invoke-MgGraphRequest -Method GET -Uri $uri
    Write-Host "processing report..."
    Start-Sleep -Seconds 1
} until ($null -ne $response2.url)

#Export report
Write-Host "Exporting report to" $OutputPath
$Report = Invoke-MgGraphRequest -Method GET -Uri $response2.url -OutputFilePath $OutputPath
