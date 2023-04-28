Get-ADObject -Filter {(msDS-AllowedToDelegateTo -like '*') -or (UserAccountControl -band 0x0080000) -or (UserAccountControl -band 0x1000000)} -Properties samAccountName,msDS-AllowedToDelegateTo,servicePrincipalName,userAccountControl `
| Select-Object DistinguishedName,ObjectClass,samAccountName,servicePrincipalName,
 @{name='DelegationStatus';expression={if($_.UserAccountControl -band 0x80000){'AllServices'}else{'SpecificServices'}}},
 @{name='AllowedProtocols';expression={if($_.UserAccountControl -band 0x1000000){'Any'}else{'Kerberos'}}},
@{name='DestinationServices';expression={$_.'msDS-AllowedToDelegateTo'}} | Where-Object { $_.DelegationStatus -eq "AllServices" }