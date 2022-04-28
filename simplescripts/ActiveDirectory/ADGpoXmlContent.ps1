

$GpoXml = gci "\\$($env:USERDNSDOMAIN)\SYSVOL\$($env:USERDNSDOMAIN)" -Recurse -Include "*.xml"


$XmlContent = @()
$GpoXml | ForEach-Object { $XmlContent += Get-Content $_.FullName }

$XmlContent | out-file .\Desktop\GpoXmlContent.txt

$GpoXml | ForEach-Object { $_.FullName; Get-Content $_.FullName | Where-Object { $_ -match "DefaultDomainName" } }
