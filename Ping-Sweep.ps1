function Ping-Sweep ($IPRanges)
{
$SavePath = "C:\Users\charles.kwiatkowski\Desktop\pingresults.txt"
$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
foreach ($IPRange in $IPRanges) {
$ping = ping -n 1 $IPRange | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } | Sort-Object -Unique 
$ping | out-file -FilePath $SavePath
}
#<#
$IPList = type C:\Users\charles.kwiatkowski\Desktop\pingresults.txt
Set-Variable -Name $IPList -Value (type C:\Users\charles.kwiatkowski\Desktop\pingresults.txt) -Scope Global
#>
}
