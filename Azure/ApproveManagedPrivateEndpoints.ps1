# Approves pending managed private endpoints in the same subscription as this is running.

param(
    [Parameter(Mandatory)]
    $WorkspaceName
)

$VerbosePreference = "Continue"

# Get subscription id so we can check approve connections in it's own subscription only where the service principal have permissions.
$SubscriptionId = (Get-AzContext).Subscription.Id

# Wait until all MPEs are provisioned.
Write-Verbose "Check so all managed private endpoints have finished the provisioning."
do {
    # Get all managed private endpoints from the Synapse API, filter out any with a destination resource outside the connected subscription.
    $ManagedPrivateEndpoints = Get-AzSynapseManagedPrivateEndpoint -WorkspaceName $WorkspaceName | Where-Object { $_.Properties.privateLinkResourceId -match $SubscriptionId }
    $ProvisioningStateCount = ($ManagedPrivateEndpoints | Where-Object { $_.Properties.provisioningState -eq "Provisioning" }).Count
    if ($ProvisioningStateCount -ge 1) {
        Write-Verbose "Found a MPE in provisiong state."
        Write-Verbose "Waiting 5 sec..."
        Start-Sleep 5
    }
} while ($ProvisioningStateCount -ge 1)

Write-Verbose "Checking for MPEs with pending connection state..."
$PendingPrivateLinkResources = ($ManagedPrivateEndpoints | Where-Object { $_.Properties.connectionState.status -eq "Pending" }).properties.privateLinkResourceId
Write-Verbose "Found {$($PendingPrivateLinkResources.count)} MPEs in pending state."

if ($PendingPrivateLinkResources.count -ge 1) {
    foreach ($PendingPrivateLinkResource in $PendingPrivateLinkResources) {
        # Get Private Link Endpoint Connections on resource
        Write-Verbose "Get Private Endpoint Connections from resource"
        Write-Verbose $PendingPrivateLinkResource
        $PrivateEndpointConnections = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $PendingPrivateLinkResource | Where-Object { $_.PrivateLinkServiceConnectionState.Status -eq 'Pending' }

        if ($PrivateEndpointConnections.Count -ge 1) {
            Write-Verbose "Found {$($PrivateEndpointConnections.Count)} pending private endpoint connections on resource."
        }

        # Approve all Private Link Endpoint Connection
        foreach ($PrivateEndpointConnection in $PrivateEndpointConnections) {
            Write-Verbose "Approving connection: $($PrivateEndpointConnection.Name)"
            Approve-AzPrivateEndpointConnection -ResourceId $PrivateEndpointConnection.id
        }
    }

    # Wait until all MPEs are approved. Retry every 10th second until a maximum of 10 minutes have passed.
    Write-Verbose "Waiting for MPEs to get approved, usually takes a few minutes..."
    $TimeoutInSeconds = 600
    $RetryCount = 0
    do {
        $RetryCount++
        Write-Verbose "Attempt {$RetryCount}"
        $ManagedPrivateEndpoints = Get-AzSynapseManagedPrivateEndpoint -WorkspaceName $WorkspaceName
        $ConnectionStatePendingCount = ($ManagedPrivateEndpoints | Where-Object { $_.Properties.connectionState.status -eq "Pending" }).Count
        if ($ConnectionStatePendingCount -ge 1) {
            Write-Verbose "Found MPE in pending connection state."
            Write-Verbose "Waiting for 10 sec..."
            Start-Sleep 10
        }
        $Timeout = $RetryCount * 10
        if ($Timeout -ge $TimeoutInSeconds) {
            throw "Approval timed out, failed to approve all MPEs..."
        }
    } while ($ConnectionStatePendingCount -ge 1)
} else {
    Write-Verbose "No MPEs in pending state found in this subscription, exiting."
}
