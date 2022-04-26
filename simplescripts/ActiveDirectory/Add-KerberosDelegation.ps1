
<#PSScriptInfo

.VERSION 1.0

.GUID c6090c89-cc19-44e4-819f-70f24a0b534b

.AUTHOR Hampus Nordanfjäll

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES ActiveDirectory,PSFramework

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


#>


<#

.DESCRIPTION 
Create and add resource based kerberos delegation

#> 

function Add-KerberosDelegation {

    <#
        .SYNOPSIS
            Add resource based kerberos delegation on computers or users for computers or users.
        .DESCRIPTION
            The Add-KerberosDelegation adds resource based delegation on existing delegations on the backend resource,
            allowing it to delegate credentials from frontend resources. Supports arrays of objects for both front and backend resources. 
            Clear computer kerberos tickets or wait 15 minutes until they are refreshed for change to take place.
        .PARAMETER BackendResourceName
            Name of resource to enable delegation on.    
        .PARAMETER FrontendResourceName
            Name of resources that backend resource will be allow delegation for.
        .EXAMPLE
            Add-KerberosDelegation -BackendResourceName 'sql1' -FrontendResourceName 'appserver1'
        .EXAMPLE
            Add-KerberosDelegation -BackendResourceName 'sql1','sql2' -FrontendResourceName 'appserver1','appserver2'
        .NOTES
            (Get-ADComputer -Identity ComputerName -Properties PrincipalsAllowedToDelegateToAccount).PrincipalsAllowedToDelegateToAccount

            Reset computer kerberos tickets
            Invoke-Command -ComputerName ComputerName -ScriptBlock {
                klist purge -li 0x3e7
                gpupdate
                
            }
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $FrontendResourceName,

        [Parameter(Mandatory)]
        [string[]] $BackendResourceName
    )

    foreach ($BackendResourceNameEntity in $BackendResourceName) {
        Write-PSFMessage -Message "Processing {$BackendResourceNameEntity}"
        $BackendResource = Get-ADObject -Filter "SamAccountName -eq '$BackendResourceNameEntity'"

        if (-Not($BackendResource.Name -eq $BackendResourceNameEntity)) {
            Write-PSFMessage -Message "Did not find a user backend resource, looking for a computer instead."
            $ComputerName = $BackendResourceNameEntity + '$'
            $BackendResource = Get-ADObject -Filter "SamAccountName -eq '$ComputerName'"
        }

        # Make sure we only have one AD object and that it matches the object we are looking for exactly.
        if ($BackendResource.Name -eq $BackendResourceNameEntity) {
            # Get AD Object and it's existing allowed delegations.
            if ($BackendResource.ObjectClass -eq "user") {
                Write-PSFMessage -Message "Backend resource is a user..."
                $ADBackendObject = Get-ADUser $BackendResource -Properties "PrincipalsAllowedToDelegateToAccount"
            } elseif ($BackendResource.ObjectClass -eq "computer") {
                Write-PSFMessage -Message "Backend resource is a computer..."
                $ADBackendObject = Get-ADComputer $BackendResource -Properties "PrincipalsAllowedToDelegateToAccount"
            } else {
                Write-PSFMessage -Message "Backend resource is something else..."
            }

            # Get existing AD objects for resources that are allowed to delegate.
            $FrontendPrincipals = @()
            if ($ADBackendObject.PrincipalsAllowedToDelegateToAccount) {
                # Get existing delegated principals
                Write-PSFMessage -Message "Found existing delegated resouces, adding them to array."
                $FrontendPrincipals += foreach ($ExistingDelegatedResource in $ADBackendObject.PrincipalsAllowedToDelegateToAccount) {
                    (Get-ADObject $ExistingDelegatedResource).DistinguishedName
                }
            } else {
                Write-PSFMessage -Message "Did not find any existing delegated resources."
            }

            # Add new frontend resources to allowed to delegate array.
            foreach ($FrontendResourceNameEntity in $FrontendResourceName) {
                Write-PSFMessage -Message "Adding new frontend resources, processing {$FrontendResourceNameEntity}."
                # Get resource, add it to array if matching user found.
                $FrontendResource = Get-ADObject -Filter "Name -eq '$FrontendResourceNameEntity'"

                if (-Not($FrontendResource.Name -eq $FrontendResourceNameEntity)) {
                    Write-PSFMessage -Message "Did not find a user frontend resource, looking for a computer instead."
                    $ComputerName = $FrontendResourceNameEntity + '$'
                    $FrontendResource = Get-ADObject -Filter "SamAccountName -eq '$ComputerName'"
                }

                # Make sure we only have one AD object and that it matches the object we are looking for exactly.
                if ($FrontendResource.Name -eq $FrontendResourceNameEntity) {
                    $FrontendPrincipals += $FrontendResource.DistinguishedName
                } else {
                    Write-PSFMessage -Message "Did not find matching frontend resource."
                }
            }

            # Set object with new array of resources allowed to delegate.
            if ($BackendResource.ObjectClass -eq "user") {
                Set-ADUser $BackendResource.DistinguishedName -PrincipalsAllowedToDelegateToAccount $FrontendPrincipals
            } elseif ($BackendResource.ObjectClass -eq "computer") {
                Set-ADComputer $BackendResource.DistinguishedName -PrincipalsAllowedToDelegateToAccount $FrontendPrincipals
            }
        } else {
            Write-PSFMessage -Message "Did not find matching AD user."
        }
    }
}
