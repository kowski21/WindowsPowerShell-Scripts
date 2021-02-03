function New-IPRange ($start, $end) 
{
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
$ip -join '.'
}
}

#Able to save output to a variable to iterate through. 