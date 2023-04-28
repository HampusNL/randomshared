
$ADUsers = Get-ADUser -Filter * -Properties servicePrincipalName,memberOf | Where-Object { $_.Enabled -eq $true -and $_.servicePrincipalName -ne $null }

# Check for high privileged role groups
$ADUsers | Out-GridView

