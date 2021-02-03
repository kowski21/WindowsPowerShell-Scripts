
$SavePath = "\\macduhpxnappx01\office_shares\J6\J63\CPT700\Cyber Threat Emulation\Ski_Test\SOCEUR\Ping_Sweep\Ping_Sweep.txt"
New-Item  $SavePath -ItemType file
$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
foreach ($IP in $IPRanges) {
"Pinging $IP"
$ping = ping -n 4 -w 300 $IP | findstr "Reply from" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
$ping | out-file -FilePath $SavePath -Append
$ping
}
#<#
$Global:IPList = type "\\macduhpxnappx01\office_shares\J6\J63\CPT700\Cyber Threat Emulation\Ski_Test\SOCEUR\Ping_Sweep\Ping_Sweep.txt"
#Set-Variable -Name $IPList -Value (type C:\Users\charles.kwiatkowski\Desktop\pingresults.txt) -Scope Global
#>
