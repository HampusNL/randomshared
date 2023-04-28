
<#PSScriptInfo

.VERSION 1.0

.GUID 6c5f2894-65a0-4ab1-baf5-c28490ab8b56

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
 Delete stale devices in Azure AD.

 1. Create App registration
 2. Delegate needed API permissions
 3. Enable public client flows for device code
 Authentication\Advanced Settings\Enable public client flows

 # Delegated permissions needed.
 Device.Read.All
 Directory.AccessAsUser.All                  # To disable and remove computers. Your admin account needs access to do this as well.

 # Application access - Not supported for disable and remove of device
 #https://learn.microsoft.com/en-us/graph/api/device-delete?view=graph-rest-1.0
 #https://learn.microsoft.com/en-us/graph/api/device-update?view=graph-rest-1.0
 #https://techcommunity.microsoft.com/t5/microsoft-365-developer-platform/add-application-permission-support-to-delete-aad-devices/idi-p/2899794
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]

param(
    [Parameter(Mandatory)]
    [int] $ThresholdDisabledDevicesDays,

    [Parameter(Mandatory)]
    [string] $TenantId,

    [Parameter(Mandatory)]
    [string] $AppClientId
)


####################


# Connect to graph
if ((Get-MgContext).Scopes -contains "Device.Read.All" -and (Get-MgContext).Scopes -contains "Directory.AccessAsUser.All") {
    Write-Verbose "Already connected to graph."
} else {
    Connect-MgGraph -ClientId $AppClientId -TenantId $TenantId -UseDeviceAuthentication -Scopes "Device.Read.All","Directory.AccessAsUser.All"
}

# Get all disabled devices so we can remove them.
# https://stackoverflow.com/questions/49764678/microsoft-graph-filter-for-onpremisesextensionattributes
# https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0&tabs=powershell
# Have to add ConsistencyLevel and Count for the filter to work.
$DisabledDevices = Get-MgDevice -Filter "startsWith(extensionAttributes/extensionAttribute1, 'DisableDate') and accountEnabled eq false" -CountVariable CountVar -ConsistencyLevel eventual

foreach ($Device in $DisabledDevices) {
    $DisableDate = Get-Date ($Device.AdditionalProperties.extensionAttributes.extensionAttribute1 -replace "DisableDate:")
    if ($DisableDate -le (Get-Date).AddDays(-$ThresholdDisabledDevicesDays)) {
        Remove-MgDevice -DeviceId $Device.Id
        if ($PSCmdlet.ShouldProcess($Device.DisplayName, "Delete device")) {
            Write-Verbose "Deleted device: $($Device.DisplayName)"
        }
    }
}
