#Create Hostname to be used later on
function Host-Name-Builder {

$HostName = ipconfig /all | findstr "Name"
$HostName = $HostName.Split("{:}").Trim()[1]
#Takes off the last 4 of the hostname should be numbers
$HostName = $HostName.Substring(0,$HostName.Length-4)

#Build an array of numbers to represent the hostname numbers
$Count += (54..83) #700 CPT Comp Names -- Modify as Needed --
$HostNum = @()
foreach ($item in $Count) 
{
$item = "{0:D4}" -f $item
$HostNum += $item
}

#Builds an array that is both the hostname and a number
$Global:HostNames = @()
foreach ($item in $HostNum) 
{
$Global:HostNames += $HostName + $item
}

}

