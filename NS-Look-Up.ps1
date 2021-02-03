function NS-Look-Up ($File)
{
$InFile = $File
$IPList = type $InFile
$OutFile = "C:\Users\charles.kwiatkowski\Desktop\Dub_Test\nslookup.txt"
$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
$DNSServer = ipconfig | findstr "Default Gateway" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } 
#<#
foreach ($IP in $IPList)
{
$NSLookUpStat = nslookup $IP
$NSLookupName = $NSLookUpStat | findstr " Name: " 
$Both = $IP + " - " + $NSLookUpName
$Both | Out-File -Append -FilePath $OutFile
}
#>
}