$devices = Get-MgDeviceManagementManagedDevice

$Results = @()
foreach ($device in $devices) {
    $deviceID = $device.id
    $params = @{
        select = @()
        skip = 0
        top = 50
        filter = "(DeviceId eq '$deviceID') and ((PolicyPlatformType eq '4') or (PolicyPlatformType eq '5') or (PolicyPlatformType eq '6') or (PolicyPlatformType eq '8') or (PolicyPlatformType eq '100'))"
        orderBy = @(
            "PolicyName asc"
        )
        search = ""
    }

    $response = Get-MgBetaDeviceManagementReportDevicePolicyComplianceReport -BodyParameter $params -outfile "c:\temp\$deviceID-test.json"

    # Step 1: Read and parse the JSON content
    $jsonContent = Get-Content -Path "C:\Temp\$deviceID-test.json" -Raw
    $data = $jsonContent | ConvertFrom-Json -Depth 10

    # Step 2: Access the specific value
    # Assuming the value is in the first row and third column of the Values array
    $policyName = $data.Values[0][2]
    State      = $data.Values[0][6]
    $user = $data.Values[0][9]


    # Collect the results
    $Results += [PSCustomObject]@{
        DeviceID   = $deviceID
        PolicyName = $policyName
        State      = $State
        User       = $user
    }
}

# Output the overview of all devices with their assignments
$Results | Format-Table -AutoSize


Get-MgBetaDeviceManagementReportConfigurationPolicyDeviceReport