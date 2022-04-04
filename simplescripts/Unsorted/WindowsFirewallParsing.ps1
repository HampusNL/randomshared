param(
    [Parameter(Mandatory)]
    $LogFolderPath
)


#region Log parse function
function Get-WinFirewallLog {
    param(
        [Parameter(Mandatory)]
        $FwLogContent
    )

    $HeaderFields = ($FwLogContent | Select-String -Pattern "#Fields: ") -split "#Fields: " | Select-Object -Last 1
    $Header = $HeaderFields -split " "
    $LogEntries = $FwLogContent | Select-Object -Skip 5 | ConvertFrom-Csv -Header $Header -Delimiter " "
    $InboundEntries = $LogEntries | Where-Object { $_.Path -eq "Receive" } | Where-Object { $_."src-ip" -notin @("::1","127.0.0.1") }
    $GroupedLogs = $InboundEntries | Group-Object -Property "dst-port","protocol","action" | Sort-Object -Property "Count" -Descending

    foreach ($Obj in $GroupedLogs) {
        $ObjProperties = $Obj | Select-Object -ExpandProperty Group | Select-Object -Last 1
        $SourceIPs = (($Obj | Select-Object -ExpandProperty Group)."src-ip" | Sort-Object -Unique) -join ","

        [PSCustomObject][Ordered]@{
            Action = $ObjProperties.action
            SourceIPs = $SourceIPs
            Protocol = $ObjProperties.protocol
            DestinationPort = $ObjProperties."dst-port"
            Count = $Obj.Count
            LastAccess = $ObjProperties.date + " " + $ObjProperties.time
        }
    }
}
#endregion

#region Load logs and group them
$LogFiles = Get-ChildItem -Path $LogFolderPath
$ParsedLogs = @()
foreach ($LogFile in $LogFiles) {
    $FWLogContent = Get-Content -Path $LogFile
    # Filter out IGMP traffic
    $ParsedLogs += Get-WinFirewallLog -FwLogContent $FWLogContent | Where-Object { $_.Protocol -ne 2 }
}
$NewObjectGroupedData = $ParsedLogs | Group-Object -Property "DestinationPort","Protocol"
$FWInfo = foreach ($Group in $NewObjectGroupedData) {
    $NewObject = $Group.Group | Sort-Object -Property "LastAccess" | Select-Object -Last 1
    $NewObject.SourceIPs = (($Group.Group.SourceIPs -join ",") -split "," | Sort-Object -Unique) -join ","
    [int]$NewObject.Count = ($Group.Group | Select-Object -ExpandProperty "Count" | Measure-Object -Sum).Sum
    $NewObject
}
#endregion


#region Filter output
# These ports should not be used so remove them from output
# 5353 o 5355 LLMNR o MDNS
# 1900 SSDP UPnP
# 123 NTP - Not needed to be opened
# UDP 500 - IPSec port - Should not be in app config
# 137, 138, 139 NETBIOS
$ExcludePorts = "139","138","137","5353","5355","1900","123","500"
$FWInfoFiltered = $FWInfo | Where-Object { $_.Protocol -ne "ICMP" } | Where-Object { $_.DestinationPort -notin $ExcludePorts }
$GroupedObjects = $FWInfoFiltered | Group-Object -Property "Protocol","DestinationPort"
$FirewallOutput = foreach ($Group in $GroupedObjects) {
    [PSCustomObject][Ordered]@{
        Protocol        = $Group.Group[0].Protocol
        DestinationPort = $Group.Group[0].DestinationPort
        Count           = [int] ($Group.Group | Select-Object -ExpandProperty "Count" | Measure-Object -Sum).Sum
        SourceIPs       = (($Group.Group.SourceIPs -join ",") -split "," | Sort-Object -Unique) -join ","
        Servers         = (($Group.Group.ComputerName -join ",") -split "," | Sort-Object -Unique) -join ","
    }
}
#endregion


#region Update existing logfile or export a new one
$FileName = "WindowsFWLog" + ".csv"
$FilePath = Join-Path -Path $LogFolderPath -ChildPath $FileName
if (Test-Path $FilePath) {
    $LogData = Import-Csv -Path $FilePath -Delimiter ";"

    $GroupedData = $LogData + $FirewallOutput | Group-Object -Property "DestinationPort","Protocol"

    # Create a new object based on last entry in the grouped data, update the info in the object and output it again.
    $FirewallOutput = foreach ($Group in $GroupedData) {
        $NewObject = $Group.Group | Select-Object -Last 1

        # Join two comma seperated arrays together, split them so we can sort and remove duplicates and then join them with comma again.
        $NewObject.SourceIPs = (($Group.Group.SourceIPs -join ",") -split "," | Sort-Object -Unique) -join ","
        $NewObject.Servers = (($Group.Group.Servers -join ",") -split "," | Sort-Object -Unique) -join ","
        $NewObject.Count = ($Group.Group | Select-Object -ExpandProperty "Count" | Measure-Object -Sum).Sum

        $NewObject
    }
    $FirewallOutput | Export-Csv -Path $FilePath -Delimiter ";" -NoTypeInformation -Force
} else {
    $FirewallOutput | Export-Csv -Path $FilePath -Delimiter ";" -NoTypeInformation
}
#endregion
