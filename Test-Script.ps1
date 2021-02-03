#Collection Script

$ScriptPath = "\\macduhpxnappx01\office_shares\J6\J63\CPT700\Cyber Threat Emulation\Ski_Test\Test_Script\System-Stalker.ps1"
$FileDropPath = "\\macduhpxnappx01\office_shares\J6\J63\CPT700\Cyber Threat Emulation\Ski_Test\Test_Drop\"

$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
$FolderName = ipconfig | findstr "IPv4" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
$HostName = hostname
$FolderName = $FolderName + " - " + $HostName

$StartTime = Get-Date

#loop to Collect data on each system
Foreach ($HostName in $HostNames){

#Builds Command to run Script
$SysStalk = Invoke-Command -ComputerName $HostName -FilePath $ScriptPath

#Executes System-Stalker Script
$SysStalk

$GatherIp = ping -n 1 $HostName
$GatherIp = $GatherIp | findstr "Reply from" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }

$FolderName = $HostName + " - " + $GatherIp

#Builds Path to Created Zip Folder
$CopyItemPath = "\\"+$HostName+"\C$\Users\Public\"+$FolderName+".zip"
#Builds Copy-Item with Variables
$CopyItem = Copy-Item -Path $CopyItemPath -Destination $FileDropPath

#Executes $CopyItem
$CopyItem

}

$EndTime = Get-Date

$StartTime
$EndTime

