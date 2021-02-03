#Collection Script

$ScriptPath = "C:\Users\charles.kwiatkowski\Desktop\Scripts\System-Stalker.ps1"
$FileDropPath = "\\macduhpxnappx01\office_shares\J6\J63\CPT700\Cyber Threat Emulation\Test_Drop\"


$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
$FolderName = ipconfig | findstr "IPv4" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
$HostName = hostname
$FolderName = $FolderName + " - " + $HostName
$System_Stalker = $env:SystemDrive+"\Users\Public\"+$FolderName

$destination = $System_Stalker + ".zip"


#loop to Collect data on each system
Foreach ($NewHostName in $HostNames){

#Builds Command to run Script
$SysStalk = Invoke-Command -ComputerName $HostName -FilePath $ScriptPath 
#Executes System-Stalker Script
$SysStalk

#Builds Path to Created Zip Folder
$CopyItemPath = "\\"+$NewHostName+"\C$\Users\Public\"+$destination

#Builds Copy-Item with Variables
$CopyItem = Copy-Item -Path $CopyItemPath -Destination $FileDropPath

#Executes $CopyItem
$CopyItem

}


