


<#
https://stackoverflow.com/questions/61474937/identify-saml-enabled-apps-in-azure-ad
OAuth apps would have a tag called "WindowsAzureActiveDirectoryIntegratedApp"
Gallery SAML Apps would have a tag called "WindowsAzureActiveDirectoryGalleryApplicationPrimaryV1"
Non-Gallery SAML Apps would have a tag called "WindowsAzureActiveDirectoryCustomSingleSignOnApplication"

https://www.ravenswoodtechnology.com/authentication-options-for-automated-azure-powershell-scripts-part-3/

# Non interactive signins
https://stackoverflow.com/questions/67302812/unable-to-get-sign-ins-for-service-principal-using-microsoft-graph-api

https://docs.microsoft.com/en-us/graph/powershell/navigating

https://docs.microsoft.com/en-us/graph/data-connect-concept-overview

batching
https://nonodename.com/post/graphapibatchcalls/

https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0

https://github.com/microsoftgraph/msgraph-sdk-powershell

#>

<# Create a new local cert you can upload to the app registration
$CertName = "ExobeHampus2024"
$Cert = New-SelfSignedCertificate -Type Custom -DnsName $CertName -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -FriendlyName $CertName -Subject $CertName
Export-Certificate -Cert $Cert -FilePath "$($env:USERPROFILE)\Desktop\$certname.cer"
#>


$Delimiter = '^' # Custom delimiter which is added to all arrays that are joined. Must never exist in the joined text strings.

$Cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match "ExobeHampus2024-9" }

$TenantId = "xxxxxxx"
$AppId = "xxxxx"


#  Permissions needed:
# "Application.Read.All", "AuditLog.Read.All", "User.Read.All", "Directory.Read.All"
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $Cert.Thumbprint

$SPProperties = "Id","KeyCredentials","DisplayName","AppId","ServicePrincipalType","Tags","ServicePrincipalNames","ReplyUrls","LogoutUrl","Oauth2Permissions","HomePage","AppRoleAssignmentRequired","PasswordCredentials","createdDateTime","AdditionalProperties","AppRoles","AppOwnerOrganizationId"
$SPs = Get-MgServicePrincipal -All -Property $SPProperties | Where-Object { $_.AppOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -and $_.ServicePrincipalType -ne "ManagedIdentity" -and $_.DisplayName -ne "P2P Server" -and $_.DisplayName -ne "YammerOnOls" -and $_.DisplayName -ne "Azure Media Service" -and $_.DisplayName -ne "O365 LinkedIn Connection" }
$AppProperties = "Id","CreatedDateTime","IsFallbackPublicCLient","PasswordCredentials","IdentifierUris","DisplayName","KeyCredentials","AppId","SignInAudience"
$Apps = Get-MgApplication -All -Property $AppProperties

$RunCount = 0
$SP = $SPs | Where-Object { $_.DisplayName -match "Microsoft Graph PowerShell" }
$Info = foreach ($SP in $SPs) {
    $RunCount ++
    Write-Verbose "Processing app {$($SP.DisplayName)} {$RunCount / $($SPs.Count)}"

    $Output = [ordered]@{
        SpDisplayName = $SP.DisplayName
        SpId = $SP.Id
        SpApplicationId = $SP.AppId
        SpType = $SP.ServicePrincipalType
        SpAppRoleAssignmentRequired = $SP.AppRoleAssignmentRequired
        SpAssignmentRequiredFalseAndAppRolesAssigned = $false
        SpCreatedDate = Get-Date ($SP.AdditionalProperties.createdDateTime) -Format "yyyy-MM-dd HH:mm"
        SpAppRolePermissions = ""
        SpAllPrincipalsDelegatedPermissions = ""
        SpSpecificDelegatedPermissions = ""
        SpAppRolesDisplayName = $SP.AppRoles.DisplayName -join $Delimiter
        SpAssignedOwnerId = ""
        SpAssignedOwnerUpn = ""
        SpAssignedToDisplayName = ""
        SpAssignedToPrincipalId = ""
        SpLastSignin = ""
        SpTotalLogins = ""
        SpAppLogins = ""
        SpUserLogins = ""
        SpTopUsers = ""
        SpAuthType = ""
        SpSamlCertificates = ""
        SpTags = $SP.Tags -join $Delimiter
        SpReplyUrls = $SP.ReplyUrls -join $Delimiter
        SpLogoutUrl = $SP.LogoutUrl -join $Delimiter
        SpEntityId = $SP.ServicePrincipalNames -join $Delimiter
        SpHomePage = $SP.HomePage
        AppDisplayName = ""
        AppId = ""
        AppSignInAudience = ""
        AppAssignedOwners = ""
        AppIsFallbackPublicCLient = ""
        AppIdentifierUris = ""
        AppKeyCredentials = ""
        AppPasswordCredentials = ""
    }

    # SAML Certificates
    if ($SP.PasswordCredentials) {
        $SamlCertificates = $SP.PasswordCredentials | Foreach-Object {
            "{0}##{1}##{2}" -f $_.DisplayName, $_.StartDateTime, $_.EndDateTime
        }
        $Output.SpSamlCertificates = $SamlCertificates -join $Delimiter
    }

    # Application API permissions
    $AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
    if ($AppRoleAssignments) {
        $SpAppRolePermissions = foreach ($AppRoleAssignment in $AppRoleAssignments) {
            (Get-MgServicePrincipal -ServicePrincipalId $AppRoleAssignment.ResourceId).AppRoles | Where-Object { $_.id -eq $AppRoleAssignment.AppRoleId } | Select-Object -ExpandProperty Value
        }
        $Output.SpAppRolePermissions = $SpAppRolePermissions -join $Delimiter
    }

    # App role assignment should not be false at the same time as app permissions have been granted to the app.
    if ($Sp.AppRoleAssignmentRequired -eq $false -and $SpAppRolePermissions -ge 1) {
        $Output.SpAssignmentRequiredFalseAndAppRolesAssigned = $true
    }

    # Delegated API permissions
    $RoleAssignmentsDelegated = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($SP.Id)'" -All
    $DelegatedRolesAllPrincipals = (($RoleAssignmentsDelegated | Where-Object { $_.ConsentType -eq "AllPrincipals" }).Scope -split " ") -join $Delimiter
    $OtherDelegatedPermissions = ($RoleAssignmentsDelegated | Where-Object { $_.ConsentType -ne "AllPrincipals" }) | Foreach-Object {
        $Scopes = $_.Scope -split " "  | Where-Object { $_ -ne '' } # In some cases a role assignment with nothing in it exists...
        $Scopes = $Scopes -join "!!" # Unique Scope array delimiter that will never exist in text string, different from main delimiter.
        "$($_.PrincipalId)##$Scopes" # Output object with custom delimiter that will never exist in text string different from above and main delimiter.
    }
    $Output.SpAllPrincipalsDelegatedPermissions = $DelegatedRolesAllPrincipals -join $Delimiter
    $Output.SpSpecificDelegatedPermissions = $OtherDelegatedPermissions -join $Delimiter

    # Enterprise App owner and user assignments.
    $Output.SpAssignedOwnerId = (Get-MgServicePrincipalOwner -ServicePrincipalId $SP.Id).Id -join $Delimiter
    $Output.SpAssignedOwnerUpn = (Get-MgServicePrincipalOwner -ServicePrincipalId $SP.Id).AdditionalProperties.userPrincipalName -join $Delimiter
    $Output.SpAssignedToDisplayName = (Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $SP.Id).PrincipalDisplayName -join $Delimiter
    $Output.SpAssignedToPrincipalId = (Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $SP.Id).PrincipalId -join $Delimiter

    # Get signin activity from audit logs.
    $Count = 0
    do {
        $Count ++
        try {
            # Still (2024-09-16) only beta endpoints that works with the new log format for application and non-interactive logins.
            $ServicePrincipalSignins = Get-MgBetaAuditLogSignIn -Filter "(appId eq '$($SP.AppId)') and (signInEventTypes/any(t: t eq 'servicePrincipal')) and status/errorCode eq 0" -Top 100 -ErrorAction "Stop"
            $UserSignins = Get-MgAuditLogSignIn -Filter "(appId eq '$($SP.AppId)') and (status/errorCode eq 0)" -Top 100 -ErrorAction "Stop"
            $UserSigninsNonInteractive = Get-MgBetaAuditLogSignIn -Filter "(appId eq '$($SP.AppId)') and (signInEventTypes/any(i:i eq 'nonInteractiveUser')) and (status/errorCode eq 0)" -Sort "createdDateTime DESC" -Top 100 -ErrorAction "Stop"

            $TopUserSignins = @()
            $TopUserSignins += $UserSignins.UserPrincipalName
            $TopUserSignins += $UserSigninsNonInteractive.UserPrincipalName

            $Output.SpTotalLogins = $ServicePrincipalSignins.Count + $UserSignins.Count + $UserSigninsNonInteractive.Count
            $Output.SpAppLogins = $ServicePrincipalSignins.Count
            $Output.SpUserLogins = $UserSignins.Count + $UserSigninsNonInteractive.Count

            $LastAppLogin = $ServicePrincipalSignins.CreatedDateTime | Select-Object -First 1
            $LastUserLogin = $UserSignins.CreatedDateTime | Select-Object -First 1
            $LastUserLogsNonInteractive = $UserSigninsNonInteractive.CreatedDateTime | Select-Object -First 1

            $LastLogin = @()
            if ($LastAppLogin -or $LastUserLogin -or $LastUserLogsNonInteractive) {
                $LastLogin += $LastAppLogin
                $lastLogin += $LastUserLogin
                $LastLogin += $LastUserLogsNonInteractive
                $LastLogin = $LastLogin | Sort-Object -Descending | Select-Object -First 1
                $LastLogin = Get-Date $LastLogin -Format "yyyy-MM-dd HH:mm:ss"
                $Output.SpLastSignin = $LastLogin
            }

            $LogError = $false

            $Output.SpTopUsers = (($TopUserSignins | Group-Object) | Sort-Object -Property "Count" -Descending | Select-Object -First 5).Name -join $Delimiter
        } catch {
            Write-Warning "Failed to read audit log attempt {$Count}, waiting and retrying..."
            $LogError = $true
            Start-Sleep 30
        }
    } until ($Count -gt 3 -or $LogError -eq $false)

    if ($LogError) {
        Write-Warning "Failed to retrieve logs for app {$($SP.DisplayName)}"
    }

    # App registration info
    $AppRegistration = $Apps | Where-Object { $_.AppId -eq $SP.AppId }
    if ($AppRegistration) {
        $Output.AppDisplayName = $AppRegistration.DisplayName
        $Output.AppAssignedOwners = (Get-MgApplicationOwner -ApplicationId $AppRegistration.Id).additionalProperties.userPrincipalName -join $Delimiter
        $Output.AppIsFallbackPublicClient = $AppRegistration.IsFallbackPublicCLient
        $Output.AppIdentifierUris = $AppRegistration.IdentifierUris -join $Delimiter
        $Output.AppSignInAudience = $AppRegistration.SignInAudience
        $Output.AppId = $AppRegistration.Id

        # Take out secret info
        if ($AppRegistration.PasswordCredentials) {
            $AppPasswordCredentialsJoined = $AppRegistration.PasswordCredentials | Foreach-Object {
                "{0}##{1}##{2}" -f $_.DisplayName, $_.StartDateTime, $_.EndDateTime
            }
            $Output.AppPasswordCredentials = $AppPasswordCredentialsJoined -join $Delimiter
        }

        # Take out authentication using private key (certificate)
        if ($AppRegistration.KeyCredentials) {
            $AppKeyCredentialsJoined = $AppRegistration.KeyCredentials | Foreach-Object {
                "{0}##{1}##{2}" -f $_.DisplayName, $_.StartDateTime, $_.EndDateTime
            }
            $Output.AppKeyCredentials = $AppKeyCredentialsJoined -join $Delimiter
        }
    }

    # Output as custom object
    [PSCustomObject]$Output
}

#$Info | Out-GridView
#$Info | Export-Csv -Path .\AppReport.csv -NoTypeInformation -Encoding UTF-8

$Info | Export-Excel -Path .\AppReport.xlsx -TableStyle Medium2 -FreezeTopRow -AutoSize
