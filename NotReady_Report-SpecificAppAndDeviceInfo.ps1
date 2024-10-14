# connect to the Microsoft Graph
connect-mggraph -Scopes "DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementApps.Read.All", "DeviceManagementApps.ReadWrite.All", "User.Read.All"

# Tenant Name  
$tenantname = (Get-mgorganization).displayName
# Collect all managed devices and filter out Windows devices that are not in the Netherlands
$windowsDevices = Get-MgBetaDeviceManagementManagedDevice | Where-Object {$_.operatingSystem -eq "windows"}
$UK_WindowsDevices = $windowsDevices | Where-Object {$_.deviceName -notlike "NL*"}

# Collect all users
$Users = (Invoke-MgGraphRequest -method Get -uri "https://graph.microsoft.com/beta/users").value 

# Collect all packaged apps
$packagedApps = Get-MgBetaDeviceAppManagementMobileApp -Filter "(isof('microsoft.graph.win32CatalogApp') or isof('microsoft.graph.windowsStoreApp') or isof('microsoft.graph.microsoftStoreForBusinessApp') or isof('microsoft.graph.officeSuiteApp') or (isof('microsoft.graph.win32LobApp') and not(isof('microsoft.graph.win32CatalogApp'))) or isof('microsoft.graph.windowsMicrosoftEdgeApp') or isof('microsoft.graph.windowsPhone81AppX') or isof('microsoft.graph.windowsPhone81StoreApp') or isof('microsoft.graph.windowsPhoneXAP') or isof('microsoft.graph.windowsAppX') or isof('microsoft.graph.windowsMobileMSI') or isof('microsoft.graph.windowsUniversalAppX') or isof('microsoft.graph.webApp') or isof('microsoft.graph.windowsWebApp') or isof('microsoft.graph.winGetApp')) and (microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true)" -Sort "displayName"

# Initialize an array to store device information
$deviceInfoList = @()
# Initialize an array to store all detected apps
$allDetectedApps = @()
# Initialize a counter for the devices
$deviceCount = $UK_WindowsDevices.Count
$count = 0

# Loop through each UK Windows device and collect user principal name and country
foreach ($device in $UK_WindowsDevices) {
    $UsageLocation = (Invoke-MgGraphRequest -method Get -uri "https://graph.microsoft.com/beta/users/$($device.userprincipalname)").UsageLocation

    if ($UsageLocation -eq "NL") {
        continue
    }
    $deviceInfo = [PSCustomObject]@{
        DeviceName = $device.deviceName
        UserPrincipalName = $device.userprincipalname
        UsageLocation = $UsageLocation
    }
    $deviceInfoList += $deviceInfo

    $count = $count + 1
    Write-output "Processing device: $($device.deviceName) - $count of $deviceCount"
    try {
        $deviceId = $device.Id
        #$detectedApps = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$deviceId')/detectedApps?\$orderBy=displayName%20asc"
        $detectedApps = Get-MgBetaDeviceManagementManagedDeviceDetectedApp -ManagedDeviceId $deviceId -All
        if ($detectedApps -ne $null) {
            $allDetectedApps += $detectedApps
        }
    } catch {
        Write-Warning "Failed to retrieve detected apps for device ID: $deviceId"
    }
}

$ExcludedPublishers = @(
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",         # Microsoft Windows
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",     # Microsoft Corporation
    "Microsoft Corporation"                                                                 # Microsoft Corporation
)

# Exclude the apps with the trusted publishers to shrink the list
$FilteredDiscoveredApps = $allDetectedApps | Where-Object { $ExcludedPublishers -notcontains $_.publisher } | select displayName, publisher, version | Sort-Object -Property displayName -Unique

# Exclude the apps with the trusted applications to shrink the list
$FilteredDiscoveredApps = $FilteredDiscoveredApps | Where-Object {$_.DisplayName -notmatch "Microsoft"}

# Get the display names of packaged apps
$packagedAppNames = $packagedApps | Select-Object -ExpandProperty displayName

# Output the filtered unique apps   
$FilteredDiscoveredApps | Sort-Object -Property displayName

# Output the device information
$deviceInfoList | Sort-Object -Property DeviceName

# Export the dirty and filtered application list and device information to CSV files
$FilteredDiscoveredApps | Export-Csv -Path "C:\temp\$tenantname-FilteredDiscoveredApps.csv" -NoTypeInformation -encoding UTF8 -delimiter ";"
$allDetectedApps | Export-Csv -Path "C:\temp\$tenantname-AllDetectedApps.csv" -NoTypeInformation -encoding UTF8 -delimiter ";"
$deviceInfoList | Export-Csv -Path "C:\temp\$tenantname-NonNLDeviceInformation.csv" -NoTypeInformation -encoding UTF8 -delimiter ";"