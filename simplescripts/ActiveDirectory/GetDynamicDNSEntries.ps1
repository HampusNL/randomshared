

$DomainName = "DNSZonNamn"
$DateThreshold = 2 # Will only get DNS entries older then this threshold



# Get all dynamic A records
$DateThresholdDate = (Get-Date).AddDays(-$DateThreshold)
$DNSEntries = Get-DnsServerResourceRecord -ZoneName $DomainName | Where-Object { $_.RecordType -eq "A" -and $_.Timestamp -le $DateThresholdDate -and $null -ne $_.TimeStamp }
$DNSEntries

# Grab all servers so we can match them faster later rather then query AD for each entry.
$ADServers = Get-ADComputer -Filter "OperatingSystem -like '*server*'" -Properties "OperatingSystem"


$ServerRecords = foreach ($DNSEntry in $DNSEntries) {
    $ADServer = $ADServers | Where-Object { $_.Name -eq $DNSEntry.HostName }

    # Output info if object found matches server
    if ($ADServer) {
        [PSCustomObject] @{
            "Name" = $DNSEntry.HostName
            "Timestamp" = Get-Date -Date $DNSEntry.Timestamp -Format "yyyy-MM-dd HH:MM" # Convert date to ISO if server region settings are something else
            "RecordData" = $DNSEntry.RecordData.IPv4Address.IPAddressToString
        }
    }
}

$ServerRecords | Export-Csv -Path "C:\DynamicDNSEntries.csv" -NoTypeInformation -Delimiter ";" -Encoding UTF8
