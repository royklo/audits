# https://ourcloudnetwork.com/defender-for-endpoint-status-report-with-microsoft-graph-powershell/
# https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/AgentStatusReportBlade

#Define the output path
$OutputPath = "C:\temp\report.zip"

#Connect to Microsoft Graph
Connect-MgGraph -Scopes DeviceManagementConfiguration.Read.All

#Define body of request, including the report name
$body = @'
{
  "filter": "",
  "format": "csv",
  "select": [
    "DeviceName",
    "_ManagedBy",
    "IsWDATPSenseRunning",
    "WDATPOnboardingState",
    "LastReportedDateTime",
    "UPN",
    "DeviceId"
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
Invoke-MgGraphRequest -Method GET -Uri $response2.url -OutputFilePath $OutputPath