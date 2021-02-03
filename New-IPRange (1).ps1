
$Global:IPRanges = @()
$start = "10.38.30.1" #Modify As Needed
$end = "10.38.30.254" #Modify As Needed

$ip1 = ([System.Net.IPAddress]$start).GetAddressBytes()
[Array]::Reverse($ip1)
$ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address
$ip2 = ([System.Net.IPAddress]$end).GetAddressBytes()
[Array]::Reverse($ip2)
$ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

for ($x=$ip1; $x -le $ip2; $x++) 
{

$ip = ([System.Net.IPAddress]$x).GetAddressBytes()
[Array]::Reverse($ip)
$IPRanges += $ip -join '.'

}
$IPRanges

#Able to save output to a variable to iterate through. 