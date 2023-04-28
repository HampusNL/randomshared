
<#PSScriptInfo

.VERSION 1.0

.GUID 104b95ae-7228-4d05-b709-3c34ac2a930a

.AUTHOR Hampus Nordanfjäll

.COMPANYNAME Exobe

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES Microsoft.Graph

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<#

.DESCRIPTION
 Disable of stale devices in Azure AD.

Pre-Reqs
1. Create App registration
2. Delegate needed API permissions
3. Enable public client flows for device code
Authentication\Advanced Settings\Enable public client flows

# Delegated permissions needed.
Device.Read.All
Directory.AccessAsUser.All                  # To disable and remove computers. Your admin account needs access to do this as well.

# Application access - Not supported for disable and remove of device.
#https://learn.microsoft.com/en-us/graph/api/device-delete?view=graph-rest-1.0
#https://learn.microsoft.com/en-us/graph/api/device-update?view=graph-rest-1.0
#https://techcommunity.microsoft.com/t5/microsoft-365-developer-platform/add-application-permission-support-to-delete-aad-devices/idi-p/2899794

# Script actions
1. Login using device code flow
2. Take out all devices older then your threshold day value.
3. Stamp current day to extensionattribute1
4. Disable stale devices.
#>


[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]

param(
    [Parameter(Mandatory)]
    [int] $ThresholdStaleDevicesDays = 190,      # Make sure its more then Intune cleanup task or add a task to remove devices in Intune.

    [Parameter(Mandatory)]
    [string] $TenantId,

    [Parameter(Mandatory)]
    [string] $AppClientId,

    [string] $OperatingSystem
)

####################


# Connect to graph
if ((Get-MgContext).Scopes -contains "Device.Read.All" -and (Get-MgContext).Scopes -contains "Directory.AccessAsUser.All") {
    Write-Verbose "Already connected to graph."
} else {
    Connect-MgGraph -ClientId $AppClientId -TenantId $TenantId -UseDeviceAuthentication -Scopes "Device.Read.All","Directory.AccessAsUser.All"
}

# Get date in ISO 8601 UTC format that we can use with Graph API.
$ThresholdDate = (Get-Date).AddDays(-$ThresholdStaleDevicesDays)
$ThresholdDateISO8601UTC = Get-Date($ThresholdDate) -Format o

# Get all devices filtered on OS and last activity.
$DevicesAll = Get-MgDevice -ConsistencyLevel "eventual" -Filter "ApproximateLastSignInDateTime le $ThresholdDateISO8601UTC and OperatingSystem eq '$OperatingSystem' and accountEnabled eq true" -All

$DevicesFilteredSynced = $DevicesAll | Where-Object { $null -eq $_.OnPremisesSyncEnabled }

# Filter out Auto Pilot devices
$AutoPilotDevices = foreach ($Device in $DevicesFilteredSynced) {
    $AutoPilot = $false
    foreach ($DevicePhysicalId in $Device.PhysicalIds) {
        if ($DevicePhysicalId -match "ZTDID") {
            $AutoPilot = $true
        }
    }

    if ($AutoPilot) { $Device }
}

# Filter away all devices that have the same name as any eventual autopilot object
$Devices = $DevicesFilteredSynced | Where-Object { $_.DisplayName -notin $AutoPilotDevices.DisplayName }

# Set current date to extensionAttribute1 so we later can safely delete machines.
$DisableDate = @{
    extensionAttributes = @{
        extensionAttribute1 = "DisableDate:" + (Get-Date -format "yyyy-MM-dd").ToString()
    }
}

foreach ($Device in $Devices) {
    if ($PSCmdlet.ShouldProcess($Device.DisplayName, "Disable device")) {
        Write-Verbose "Disabling device: $($Device.DisplayName) with last activity: $($Device.ApproximateLastSignInDateTime)"
        Update-MgDevice -DeviceId $Device.Id -BodyParameter $DisableDate
        Update-MgDevice -DeviceId $Device.Id -AccountEnabled:$false
    }
}
