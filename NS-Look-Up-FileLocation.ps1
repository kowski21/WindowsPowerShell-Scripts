function NS-Look-Up-FileLocation ($FileLocation)
{
$InFile = $FileLocation
$IPList = type $InFile
$OutFile = "C:\Users\charles.kwiatkowski\Desktop\Dub_Test\nslookup.txt"
#$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
#$DNSServer = ipconfig | findstr "Default Gateway" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } 
$DNSServer = $env:USERDNSDOMAIN

#<#
foreach ($IP in $IPList)
{
$NSLookUpStat = nslookup $IP $DNSServer
$NSLookupName = $NSLookUpStat | findstr " Name: " 
$Both = $IP + " - " + $NSLookUpName
$Both | Out-File -Append -FilePath $OutFile
}
#>
}
