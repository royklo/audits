# Variables
# $Tenant_id = "e1aeec54-8472-4025-9de4-662e09e78d7a"
# $client_id = "9205eae6-23c8-4cbb-bf2b-edc0ffe4cc02"
# $client_secret = ""
# $sharedKey = ""
# $CustomerID = "a6de0f04-4383-4f7d-a252-ab83b5454f3f"           # called workspaceID in Azure Log Analytics Workspace

# # Authentication
# $SecuredPasswordPassword = ConvertTo-SecureString `
#     -String $client_secret -AsPlainText -Force
 
# $ClientSecretCredential = New-Object `
#     -TypeName System.Management.Automation.PSCredential `
#     -ArgumentList $client_id, $SecuredPasswordPassword
 
#Connect-MgGraph #-TenantId $Tenant_id -ClientSecretCredential $ClientSecretCredential

# Collect all user ID and UPNs
$AllEntraIDUsers = Get-MgUser -All -Property @("Id", "UserPrincipalName")

function Get-AllDeviceData {

    #Get tenant name From Microsoft Entra ID
    $TenantName = (Get-MgOrganization).displayname

    #Retrieve all properties
    $Properties = @('AadRegistered', 'hardwareInformation', 'ActivationLockBypassCode', 'AndroidSecurityPatchLevel', 'AndroidSecurityPatchLevel', 'AssignmentFilterEvaluationStatusDetails', 'AutopilotEnrolled', 'AzureActiveDirectoryDeviceId', 'AzureAdDeviceId', 'AzureAdRegistered', 'BootstrapTokenEscrowed', 'ChassisType', 'ChromeOSDeviceInfo', 'ComplianceGracePeriodExpirationDateTime', 'ComplianceState', 'ConfigurationManagerClientEnabledFeatures', 'ConfigurationManagerClientHealthState', 'ConfigurationManagerClientInformation', 'DetectedApps', 'DeviceActionResults', 'DeviceCategory', 'DeviceCategoryDisplayName', 'DeviceCompliancePolicyStates', 'DeviceConfigurationStates', 'DeviceEnrollmentType', 'DeviceFirmwareConfigurationInterfaceManaged', 'DeviceHealthAttestationState', 'DeviceName', 'DeviceRegistrationState', 'DeviceType', 'EasActivated', 'EasActivationDateTime', 'EasDeviceId', 'EmailAddress', 'EnrolledDateTime', 'EnrollmentProfileName', 'EthernetMacAddress', 'ExchangeAccessState', 'ExchangeAccessStateReason', 'ExchangeLastSuccessfulSyncDateTime', 'FreeStorageSpaceInBytes', 'Iccid', 'Id', 'Imei', 'IsEncrypted', 'IsSupervised', 'JailBroken', 'JoinType', 'LastSyncDateTime', 'LogCollectionRequests', 'LostModeState', 'ManagedDeviceMobileAppConfigurationStates', 'ManagedDeviceName', 'ManagedDeviceOwnerType', 'ManagementAgent', 'ManagementCertificateExpirationDate', 'ManagementFeatures', 'ManagementState', 'Manufacturer', 'Meid', 'Model', 'Notes', 'OSVersion', 'OperatingSystem', 'OwnerType', 'PartnerReportedThreatState', 'PhoneNumber', 'PhysicalMemoryInBytes', 'PreferMdmOverGroupPolicyAppliedDateTime', 'ProcessorArchitecture', 'RemoteAssistanceSessionErrorDetails', 'RemoteAssistanceSessionUrl', 'RequireUserEnrollmentApproval', 'RetireAfterDateTime', 'RoleScopeTagIds', 'SecurityBaselineStates', 'SerialNumber', 'SkuFamily', 'SkuNumber', 'SpecificationVersion', 'SubscriberCarrier', 'TotalStorageSpaceInBytes', 'Udid', 'UserDisplayName', 'UserId', 'UserPrincipalName', 'Users', 'UsersLoggedOn', 'WiFiMacAddress', 'WindowsActiveMalwareCount', 'WindowsProtectionState', 'WindowsRemediatedMalwareCount')

    #Get all Windows Devices from Microsoft Intune
    $AllDeviceData = Get-MgDeviceManagementManagedDevice -Filter "OperatingSystem eq 'Windows'" -All 

    # Get all AutoPilot registered devices under "Enrollment"
    $AutopilotDevices = (Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities").value

    function Get-OperatingSystemProductType {
        param (
            $Customer
        )

        @{ 
            "0"   = "unknown"
            "4"   = "Windows 10/11 Enterprise"
            "27"  = "Windows 10/11 Enterprise N"
            "48"  = "Windows 10/11 Professional"
            "49"  = "Windows 10/11 Professional for workstation N"
            "72"  = "Windows 10/11 Enterprise Evaluation"
            "119" = "Windows 10 TeamOS"
            "121" = "Windows 10/11 Education"
            "122" = "Windows 10/11 Education N"
            "125" = "Windows 10 Enterprise LTSC"
            "136" = "Hololens"
            "175" = "Windows 10 / 11 Enterprise Multi-session"
        }.$Customer
    }
    
    function Convert-Size {            
        [cmdletbinding()]            
        param(            
            [validateset("Bytes", "KB", "MB", "GB", "TB")]            
            [string]$From,            
            [validateset("Bytes", "KB", "MB", "GB", "TB")]            
            [string]$To,            
            [Parameter(Mandatory = $true)]            
            [double]$Value,            
            [int]$Precision = 4            
        )            
        switch ($From) {            
            "Bytes" { $value = $Value }            
            "KB" { $value = $Value * 1024 }            
            "MB" { $value = $Value * 1024 * 1024 }            
            "GB" { $value = $Value * 1024 * 1024 * 1024 }            
            "TB" { $value = $Value * 1024 * 1024 * 1024 * 1024 }            
        }            
                    
        switch ($To) {            
            "Bytes" { return $value }            
            "KB" { $Value = $Value / 1KB }            
            "MB" { $Value = $Value / 1MB }            
            "GB" { $Value = $Value / 1GB }            
            "TB" { $Value = $Value / 1TB }            
                    
        }            
          
        $Calc = [Math]::Round($value, $Precision, [MidPointRounding]::AwayFromZero) 
        return "$calc $to" 
                    
    }

    # Loop trough all devices for device data
    $results = @()

    foreach ($DeviceData in $AllDeviceData) {
        $currentIndex = [array]::IndexOf($AllDeviceData, $DeviceData) + 1
        $totalDevices = $AllDeviceData.Count
        Write-Host "Working on device $($DeviceData.DeviceName) - $currentIndex of $totalDevices"

        $DeviceProperties = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/manageddevices/$($DeviceData.id)?`$select=$($Properties -join ',')"   
        $AutopilotInfo = $AutopilotDevices | Where-Object { $_.serialnumber -eq $devicedata.SerialNumber } 

        $rule = $null

        #check if device is compliant or not. If not compliant it will check for which rule its not compliant.
        $FilteredForAlerting = "DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned", "DefaultDeviceCompliancePolicy.RequireRemainContact"

        if ($DeviceData.complianceState -eq "noncompliant") {
            $ComplianceRules = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($DeviceData.id)/deviceCompliancePolicyStates").value | Where-Object { $_.State -eq "nonCompliant" -or $_.State -eq "Error" }
            if ($ComplianceRules.count -gt 10) {
            }
            else {
                foreach ($ComplianceRule in $ComplianceRules) {
                    $rule = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($DeviceData.id)/deviceCompliancePolicyStates/$($ComplianceRule.id)/settingStates").value | Where-Object { $_.state -match 'nonCompliant' }
                }
            }
        }

        # Check if all logged in user ID's still exist in Microsoft Entra ID
        $LoggedInUsers = $DeviceProperties.usersLoggedOn.userId | Select-Object -Unique
        $ExistingLoggedInUsers = @()

        foreach ($user in $LoggedInUsers) {
            if ($user -in $AllEntraIDUsers.Id) {
                # User exists in Entra, add to array
                #Write-Host "$user found" -ForegroundColor Green
                $ExistingLoggedInUsers += (Get-MgUser -UserId $user).userprincipalname
            }
            else {
                #Write-Host "$user not found" -ForegroundColor Cyan
            }
        }

        $results += [PSCustomObject][ordered]@{
            Customer                   = $TenantName
            DeviceName                 = $DeviceProperties.DeviceName
            DeviceOwnership            = $DeviceProperties.ManagedDeviceOwnerType
            PrimaryUser                = $DeviceProperties.UserPrincipalName
            Serialnumber               = $DeviceProperties.SerialNumber
            DeviceManufacturer         = $DeviceProperties.Manufacturer
            DeviceModel                = $DeviceProperties.Model
            ProcessorArchitecture      = $DeviceProperties.processorArchitecture
            TPMversion                 = $DeviceProperties.hardwareInformation.tpmVersion
            tpmSpecificationVersion    = $DeviceProperties.hardwareInformation.tpmSpecificationVersion
            WiFiMAC                    = $DeviceProperties.WiFiMacAddress
            EthernetMAC                = $DeviceProperties.EthernetMacAddress
            TotalStorage               = Convert-Size -From bytes -To GB -Value $DeviceProperties.TotalStorageSpaceInBytes -Precision 2
            FreeStorage                = Convert-Size -From bytes -To GB -Value $DeviceProperties.FreeStorageSpaceInBytes -Precision 2  
            EnrolledDate               = $DeviceProperties.EnrolledDateTime | Get-Date -Format "dd-MM-yyyy hh:mm"
            LastContact                = $DeviceProperties.LastSyncDateTime | Get-Date -Format "dd-MM-yyyy hh:mm"
            AutopilotGroupTag          = $AutopilotInfo.groupTag
            AutopilotAssignedUser      = if ($AutopilotInfo.userprincipalname) { $AutopilotInfo.userprincipalname } else { $null }
            EnrollmentProfile          = $DeviceProperties.EnrollmentProfileName
            Encrypted                  = $DeviceProperties.IsEncrypted
            DeviceEnrollmentType       = $DeviceProperties.DeviceEnrollmentType 
            #BitlockerRecovery      = Not yet possible only user auth flow.
            #usersLoggedOnIds           = $DeviceProperties.usersLoggedOn.userId | Select-Object -Unique
            usersLoggedOnIds           = $($ExistingLoggedInUsers).split(",") -join ', '
            usersLoggedOnCount         = ($DeviceProperties.usersLoggedOn.userId | Select-Object -Unique).count
            Operatingsystem            = $DeviceProperties.OperatingSystem
            OperatingSystemVersion     = $DeviceProperties.OSVersion
            OperatingSystemLanguage    = $DeviceProperties.hardwareInformation.operatingSystemLanguage
            OperatingSystemEdition     = $DeviceProperties.hardwareInformation.operatingSystemEdition
            operatingSystemProductType = Get-OperatingSystemProductType -Customer "$($DeviceProperties.hardwareInformation.operatingSystemProductType)"
            BiosVersion                = $DeviceProperties.hardwareInformation.systemManagementBIOSVersion
            #PhoneNumber                = $(if ($DeviceProperties.usersLoggedOn.Count -eq 1 ) { (Get-MgUserAuthenticationPhoneMethod -UserId $DeviceProperties.usersLoggedOn.userId).PhoneNumber })
            ComplianceStatus           = $DeviceProperties.ComplianceState
            NoncompliantBasedOn        = $rule.setting -join ', '
            NoncompliantAlert          = ($rule.setting | Where-Object { $_ -notin $FilteredForAlerting }) -join ', '
            Log                        = 'Device data'
            Name                       = 'Device Compliancy'
        }
    }

    $results

}

# Function _SendToLogAnalytics {
#     [cmdletBinding(SupportsShouldProcess)]
#     Param(
#         # Workspace Id for the Log Analytics workspace
#         [string]$customerId,
#         # Primary key to allow writing to the workspace
#         [string]$sharedKey,
#         # The actual log in JSON format
#         [string]$logs,
#         # Defines the name for the Custom Log 
#         [string]$logType,
#         # When not empty, the name of the field to use as the Generated timestamp
#         [string]$timeStampField = ''
#     )
#     # Generate the body for the Invoke-WebRequest
#     $body = ([System.Text.Encoding]::UTF8.GetBytes($Logs))
#     $method = 'POST'
#     $contentType = 'application/json'
#     $resource = '/api/logs'
#     $rfc1123date = [DateTime]::UtcNow.ToString('r')
#     $contentLength = $body.Length
  
#     #Create the encoded hash to be used in the authorization signature
#     $xHeaders = "x-ms-date:" + $rfc1123date
#     $stringToHash = ($method, $contentLength, $contentType, $xHeaders, $resource) -join "`n"
#     $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
#     $keyBytes = [Convert]::FromBase64String($sharedKey)
#     $sha256 = New-Object System.Security.Cryptography.HMACSHA256
#     $sha256.Key = $keyBytes
#     $calculatedHash = $sha256.ComputeHash($bytesToHash)
#     $encodedHash = [Convert]::ToBase64String($calculatedHash)
#     $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
  
#     # Create the uri for the data insertion endpoint for the Log Analytics workspace
#     $uri = 'https://{0}.ods.opinsights.azure.com{1}?api-version=2016-04-01' -f $customerId, $resource
  
#     # Create the headers to be used in the Invoke-WebRequest
#     $Headers = @{
#         'Authorization' = $authorization
#         'Log-Type'      = $logType
#         'x-ms-date'     = $rfc1123date
#     }
  
#     if (-not [string]::IsNullOrEmpty($timeStampField)) {
#         $Headers['time-generated-field'] = $timeStampField
#     }
  
#     # Try to send the logs to the Log Analytics workspace
#     Write-Verbose "$Method $uri`nHeaders:`n$($Headers|Out-String)"
#     if ($PSCmdlet.ShouldProcess($Uri, 'Invoke-WebRequest')) {
#         Try {    
#             $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing -ErrorAction stop
#         }
#         # Catch any exceptions and write them to the output 
#         Catch {
#             Throw "$($_.Exception)"
#         }
#         # Return the status code of the web request response
#         Return $response
#     }
# }

$CollectedData = Get-AllDeviceData


# if ([string]::IsNullOrEmpty($CollectedData)) {
#     Write-Verbose "Nothing to upload"
# }
# else {
    
#     $null = _SendToLogAnalytics -CustomerId $customerId -SharedKey $sharedKey -Logs ($CollectedData | ConvertTo-Json -Depth 10) -LogType 'IntuneTest_DeviceData' 
# }

#Disconnect-MgGraph