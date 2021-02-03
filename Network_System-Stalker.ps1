#Code Name: Network_System_Stalker.ps1
#Global Save location; Modify as needed
#starts in C:\Users so that it is able to pick up on userdata as opposed to the whole drive, unless need whole drive.
$ScanDir = $env:SystemDrive+"\Users\*"
$i = 0
#Create New Folder
$regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
$FolderName = ipconfig | findstr "IPv4" | Select-String -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
$HostName = hostname
$FolderName = $FolderName + " - " + $HostName
$System_Stalker = $env:SystemDrive+"\"+$FolderName
New-Item  $System_Stalker -ItemType directory | Out-Null
#Pull File Types:
#File Types are those you want to look for. Modify as needed
#--- ORIGINAL --- $FileTypes = "*.pdf","*.txt","*.doc","*.docx","*.xls","*.xlsx","*.jpg","*.jpeg","*.gif","*.bmp","*.exe","*.zip","*.7z" --- ORIGINAL ---
$FileTypes = "*.pdf","*.txt","*.doc","*.docx","*.xls","*.xlsx","*.jpg","*.jpeg","*.gif","*.bmp","*.exe","*.zip","*.7z"
#Iterate through the list of FileTypes
foreach ($FileType in $FileTypes)
{
if($i+1 -le 9)
{
$f = $i+1 
$FileName="0"+$f.ToString()+"_"+$FileTypes[$i].substring(2)+"_Files.txt"
}
Else 
{ 
$f = $i+1 
$FileName=$f.ToString()+"_"+$FileTypes[$i].substring(2)+"_Files.txt"
}
#}
$Heading = $H1 + $Starting + $FileType + "'s " + $H1
$SaveLocation = $System_Stalker+"\"+$FileName
$Search = Get-ChildItem -path $ScanDir -Recurse -Include $FileType | Sort-Object LastWriteTime -Descending | Format-Table Fullname,LastWriteTime -AutoSize | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation
#Increment variable
$i=$i+1
}
#Collect Users:
$i = $i+1
$FileName=$i.ToString()+"_All_Users.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$CreateList = Get-ChildItem -Path $ScanDir | Where-Object {$_.Name -like "*"} | Sort-Object LastWriteTime -Descending | Format-Table Fullname,LastWriteTime -AutoSize | where {$_ -ne ""}
$CreateList | Out-File -Append -FilePath $SaveLocation

#List Users whos name appears as *.adm:
$i = $i+1
$FileName=$i.ToString()+"_Adm_Users.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$CreateList = Get-ChildItem -Path $ScanDir | Where-Object {$_.Name -like "*.adm"} | Sort-Object LastWriteTime -Descending | Format-Table Fullname,LastWriteTime -AutoSize| where {$_ -ne ""}
$CreateList | Out-File -Append -FilePath $SaveLocation

#Prefetch Data
$i = $i+1
$FileName=$i.ToString()+"_Prefetch_Data.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$Search = Get-ChildItem -path $env:SystemRoot\prefetch | Sort-Object LastWriteTime -Descending | Format-Table Fullname -AutoSize | Out-String -Width 1024 | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation

#Collection of MOF files:
$i = $i+1
$FileName=$i.ToString()+"_Mof_Files.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$Search = Get-ChildItem -path $env:SystemRoot\System32\wbem -Recurse -Include "*.mof" | Sort-Object LastWriteTime -Descending | Format-Table Fullname -auto | Out-String -Width 1024 | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation

#Gather IP Information
$i = $i+1
$FileName=$i.ToString()+"_IP_All.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$IPInfo = ipconfig /all | where {$_ -ne ""}
$IPInfo | Out-File -Append -FilePath $SaveLocation

#Gather Systeminfo
$i = $i+1
$FileName=$i.ToString()+"_SysInfo_!Hotfixes.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$SystemInfo = systeminfo | findstr /v "KB" | where {$_ -ne ""}
$SystemInfo | Out-file -Append -FilePath $SaveLocation

#Gather Group Policy Results
$i = $i+1
$FileName=$i.ToString()+"_GpResult_R.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$GPResult = gpresult /R | where {$_ -ne ""}
$GPResult | Out-file -Append -FilePath $SaveLocation

#Gather Group Policy Users
$i = $i+1
$FileName=$i.ToString()+"_GpResult_Sc_User_Z.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$GPResultUser = gpresult /Scope User /Z | where {$_ -ne ""}
$GPResultUser | Out-file -Append -FilePath $SaveLocation

#Gather Group Policy Computers
$i = $i+1
$FileName=$i.ToString()+"_GpResult_Sc_Comp_Z.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$GPResultComp = gpresult /Scope Computer /Z | where {$_ -ne ""}
$GPResultComp | Out-file -Append -FilePath $SaveLocation

#Gather Net Share
$i = $i+1
$FileName=$i.ToString()+"_Net_Share.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetShare = net share | findstr /v " -" | findstr /v "The " | where {$_ -ne ""}
$NetShare | Out-file -Append -FilePath $SaveLocation

#Gather Net User
$i = $i+1
$FileName=$i.ToString()+"_Net_User.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetUser = net user | findstr /v " -" | findstr /v "The " | where {$_ -ne ""} 
$NetUser | Out-file -Append -FilePath $SaveLocation

#Gather Net Local Group
$i = $i+1
$FileName=$i.ToString()+"_Net_Group.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetLocalGroup = net localgroup | findstr /v " -" | findstr /v "The " | where {$_ -ne ""}
$NetLocalGroup | Out-file -Append -FilePath $SaveLocation

#Gather Net Accounts
$i = $i+1
$FileName=$i.ToString()+"_Net_Accounts.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetAccounts = net accounts | findstr /v "The " | where {$_ -ne ""}
$NetAccounts | Out-file -Append -FilePath $SaveLocation

#Gather Net Accounts Domain
$i = $i+1
$FileName=$i.ToString()+"_Net_Accounts_Domain.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetAccountsDomain = net accounts /domain | findstr /v "The " | where {$_ -ne ""}
$NetAccountsDomain | Out-file -Append -FilePath $SaveLocation

#Gather Net config workstation
$i = $i+1
$FileName=$i.ToString()+"_Net_Config_WRKS.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetAccountsDomain = net config workstation | findstr /v "The " | where {$_ -ne ""} <#Server for servers#> 
$NetAccountsDomain | Out-file -Append -FilePath $SaveLocation

#Gather Net file
$i = $i+1
$FileName=$i.ToString()+"_Net_File.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetFile = net file | where {$_ -ne ""}
$NetFile | Out-file -Append -FilePath $SaveLocation

#Gather Driver Data
$i = $i+1
$FileName=$i.ToString()+"_Driver_Query_v.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$DriverQueryV = driverquery /v /FO CSV | ConvertFrom-Csv | findstr /v "Init(bytes)" | findstr /v "Code(bytes)" | findstr /v "Paged Pool(bytes)" | findstr /v "BSS(bytes)" | findstr /v "Description" | findstr /v "State" | findstr /v "Status" | findstr /v "Accept"
$DriverQueryV | Out-File -Append -FilePath $SaveLocation

#Gather Signed Info
$i = $i+1
$FileName=$i.ToString()+"_Driver_Query_signed.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$DriverQuerySI = driverquery /si /FO CSV | ConvertFrom-Csv | Format-Table -AutoSize
$DriverQuerySI | Out-file -Append -FilePath $SaveLocation

#Gather Netstat Info
$i = $i+1
$FileName=$i.ToString()+"_Netstat_anop_tcp.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetstatANOP = netstat -anop tcp | findstr /v "127.0.0.1" | findstr /v "0.0.0.0" | where {$_ -ne ""}
$NetstatANOP | Out-file -Append -FilePath $SaveLocation

#Gather More netstat Info
$i = $i+1
$FileName=$i.ToString()+"_Netstat_anob.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetstatANOB = netstat -anob | where {$_ -ne ""}
$NetstatANOB | Out-file -Append -FilePath $SaveLocation

#Gather Tasklisting
$i = $i+1
$FileName=$i.ToString()+"_tasklist.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$TaskList = tasklist | where {$_ -ne ""}
$TaskList | Out-file -Append -FilePath $SaveLocation

#Reg Queries
$i = $i+1
$Filler = "-------------------------------------------------"
$FileName=$i.ToString()+"_Reg_Run_Queries.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$HKLMRun = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s | where {$_ -ne ""}
$HKLMRun | Out-file -Append -FilePath $SaveLocation

$Filler | Out-File -Append -FilePath $SaveLocation
$HKLMRunOnce = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | where {$_ -ne ""}
$HKLMRunOnce | Out-file -Append -FilePath $SaveLocation

$Filler | Out-File -Append -FilePath $SaveLocation
$HKCURun = reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s | where {$_ -ne ""}
$HKCURun | Out-file -Append -FilePath $SaveLocation

$Filler | Out-File -Append -FilePath $SaveLocation
$HKCURunOnce = reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | where {$_ -ne ""}
$HKCURunOnce | Out-file -Append -FilePath $SaveLocation

$Filler | Out-File -Append -FilePath $SaveLocation
$HKURun = reg query HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run /s
$HKURun | Out-file -Append -FilePath $SaveLocation

#Netsh Infromation Gathering

#Gather Netsh advfirewall firewall show rule name=all (Only Names)
$i = $i+1
$FileName=$i.ToString()+"_Netsh_Adv_Fire_Rule_Name.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$AdvFirewallRuleNames = Netsh advfirewall firewall show rule name=all | findstr "Rule Name:" | Sort-Object -Unique | where {$_ -ne ""}
$AdvFirewallRuleNames | Out-file -Append -FilePath $SaveLocation

<# Disabled unless needed to pull rule information
#Gather Netsh advfirewall firewall show rule name=all
$i = $i+1
$FileName=$i.ToString()+"_Netsh_Adv_Fire_Rule_Info.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$AdvFirewallRules = Netsh advfirewall firewall show rule name=all  
$AdvFirewallRules | Out-file -Append -FilePath $SaveLocation
#>

#Gather Netsh lan show interfaces
$i = $i+1
$FileName=$i.ToString()+"_Netsh_Lan_Interfaces.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$LanInt = netsh lan show interfaces | where {$_ -ne ""}
$LanInt | Out-file -Append -FilePath $SaveLocation

#Gather Netsh lan show profiles
$i = $i+1
$FileName=$i.ToString()+"_Netsh_Lan_Show_Prof.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$LanProfiles = netsh lan show profiles | where {$_ -ne ""}
$LanProfiles | Out-file -Append -FilePath $SaveLocation

#Gather Netsh lan show settings
$i = $i+1
$FileName=$i.ToString()+"_Netsh_Lan_Show_Settings.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$LanSettings = netsh lan show settings | where {$_ -ne ""}
$LanSettings | Out-file -Append -FilePath $SaveLocation

#Gather Netsh wlan show all
$i = $i+1
$FileName=$i.ToString()+"_Netsh_wlan_show_all.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WlanAll = netsh wlan show all | where {$_ -ne ""}
$WlanAll | Out-file -Append -FilePath $SaveLocation

#Gather Netstat -ab
$i = $i+1
$FileName=$i.ToString()+"_Netstat_ab.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetStatAB = netstat -ab | where {$_ -ne ""}
$NetStatAB | Out-file -Append -FilePath $SaveLocation

#Gather Netstat -aon
$i = $i+1
$FileName=$i.ToString()+"_Netstat_aon.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$NetStatAON = netstat -aon | findstr /v "*:*" | findstr /v ":0" | findstr /v "127.0.0.1" | where {$_ -ne ""}
$NetStatAON | Out-file -Append -FilePath $SaveLocation

#Gather Query session
$i = $i+1
$FileName=$i.ToString()+"_Query_Session.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$QuerySession = query session | where {$_ -ne ""}
$QuerySession | Out-file -Append -FilePath $SaveLocation

#Gather Query User
$i = $i+1
$FileName=$i.ToString()+"_Query_User.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$QueryUser = query user | where {$_ -ne ""}
$QueryUser | Out-file -Append -FilePath $SaveLocation

#Gather Query process
$i = $i+1
$FileName=$i.ToString()+"_Query_Process.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$QueryProcess = query process | where {$_ -ne ""}
$QueryProcess | Out-file -Append -FilePath $SaveLocation

#Gather Wmic startup
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Startup.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicStartup = wmic startup get "Caption,Command,Location,User,UserSID" | where {$_ -ne ""}
$WmicStartup | Out-file -Append -FilePath $SaveLocation

#Gather Wmic sysaccount
$i = $i+1
$FileName=$i.ToString()+"_Wmic_SysAccount.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicSysAccount = wmic sysaccount get "Caption,Description,Domain,LocalAccount,Name,SID,SIDType,Status" | where {$_ -ne ""}
$WmicSysAccount | Out-file -Append -FilePath $SaveLocation

#Gather Wmic csproduct
$i = $i+1
$FileName=$i.ToString()+"_Wmic_CsProduct.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicCsProduct = wmic csproduct get "Caption,IdentifyingNumber,Name,UUID,Vendor" | where {$_ -ne ""}
$WmicCsProduct | Out-file -Append -FilePath $SaveLocation

#Gather Wmic environment
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Env.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicEnv = wmic environment get "Caption,Description,Name,SystemVariable,UserName,VariableValue" | where {$_ -ne ""}
$WmicEnv | Out-file -Append -FilePath $SaveLocation

<#Gather Wmic group
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Group.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicGroup = wmic group get "Caption,Description,Domain,LocalAccount,Name,SID,SIDType,Status" | where {$_ -ne ""}
$WmicGroup | Out-file -Append -FilePath $SaveLocation
#>

#Gather Wmic logicaldisk
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Logical_Disk.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicLogicalDisk = wmic logicaldisk get "Name,Compressed,CreationClassName,Description,DriveType,FileSystem" | where {$_ -ne ""}
$WmicLogicalDisk | Out-file -Append -FilePath $SaveLocation

#Gather Wmic nic
$i = $i+1
$FileName=$i.ToString()+"_Wmic_NIC.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicNic = wmic nic get "Name,Description,Manufacturer,MACAddress,NetConnectionID,NetEnabled,NetworkAddresses,PermanentAddress,PNPDeviceID,ProductName,ServiceName" | where {$_ -ne ""}
$WmicNic | Out-file -Append -FilePath $SaveLocation

#Gather Wmic nicconfig
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Nicconfig.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicNicConfig = wmic nicconfig get "Description,DatabasePath,DefaultIPGateway,DHCPServer,DNSDomain,DNSDomainSuffixSearchOrder,DNSHostName,DNSServerSearchOrder,IPAddress,IPSubnet,ServiceName" | where {$_ -ne ""}
$WmicNicConfig | Out-file -Append -FilePath $SaveLocation

#Gather Wmic ntdomain
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Nt_Domain.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicNTDomain = wmic ntdomain | where {$_ -ne ""}
$WmicNTDomain | Out-file -Append -FilePath $SaveLocation

#Gather Wmic os
$i = $i+1
$FileName=$i.ToString()+"_Wmic_OS.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicOS = wmic os get "Name,Caption,Version,MUILanguages,OSArchitecture,RegisteredUser" | where {$_ -ne ""}
$WmicOS | Out-file -Append -FilePath $SaveLocation

#Gather Wmic partition
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Partition.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicPartition = wmic partition get "Caption,DeviceID,Description,PrimaryPartition,SystemName" | where {$_ -ne ""}
$WmicPartition | Out-file -Append -FilePath $SaveLocation

#Gather wmic printerconfig
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Printer_Config.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicPrinterConf = wmic printerconfig get "DeviceName,DriverVersion" | where {$_ -ne ""}
$WmicPrinterConf | Out-file -Append -FilePath $SaveLocation

#Gather wmic printer
$i = $i+1
$FileName=$i.ToString()+"_wmic_Printer.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicPrinter = wmic printer get "Caption,CreationClassName" | where {$_ -ne ""}
$WmicPrinter | Out-file -Append -FilePath $SaveLocation

#Gather wmic process
$i = $i+1
$FileName=$i.ToString()+"_wmic_Process.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicProcess = wmic process get "Name,Caption,CommandLine,WindowsVersion,CSName,Description,ExecutablePath,OSName" | where {$_ -ne ""}
$WmicProcess | Out-file -Append -FilePath $SaveLocation

#Gather wmic product get
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Product.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicProduct = wmic product get "Caption,Description,Version,InstallLocation,LocalPackage,Name,PackageName" | where {$_ -ne ""}
$WmicProduct | Out-file -Append -FilePath $SaveLocation

#Gather wmic rdnic
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Rd_Nic.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicRdNic = wmic rdnic get "TerminalName,NetworkAdapterName,NetworkAdapterList,DeviceIDList" | where {$_ -ne ""}
$WmicRdNic | Out-file -Append -FilePath $SaveLocation

#Gather wmic rdaccount
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Rd_Account.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicRdAccount = wmic rdaccount get "AccountName,SID,TerminalName" | where {$_ -ne ""}
$WmicRdAccount | Out-file -Append -FilePath $SaveLocation

#Gather wmic rdpermissions
$i = $i+1
$FileName=$i.ToString()+"_Wmic_Rd_Permissions.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$WmicRdPermissions = wmic rdpermissions | where {$_ -ne ""}
$WmicRdPermissions | Out-file -Append -FilePath $SaveLocation

#Gather schtasks
$i = $i+1
$FileName=$i.ToString()+"_Scheduled_Task_List.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$SchTasks = schtasks | where {$_ -ne ""}
$SchTasks | Out-file -Append -FilePath $SaveLocation

#Gather AD Information
$i = $i+1
$FileName=$i.ToString()+"_AD_Groups.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$ADGroup = Get-ADGroup -Filter * | findstr "Name" | findstr /v "SamAccountName" | findstr /v "DistinguishedName" | Sort-Object -Unique
$ADGroup | Out-file -Append -FilePath $SaveLocation

$i = $i+1
$FileName=$i.ToString()+"_AD_Domain_Controller.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$ADDomainController = Get-ADDomainController | findstr /v "IPv6Address"
$ADDomainController | Out-file -Append -FilePath $SaveLocation

$i = $i+1
$FileName=$i.ToString()+"_AD_Root_DSE.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$ADRootDSE = Get-ADRootDSE
$ADRootDSE | Out-file -Append -FilePath $SaveLocation

$i = $i+1
$FileName=$i.ToString()+"_AD_Org_OU.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$ADOrgUnit = Get-ADOrganizationalUnit -Filter * | findstr "Name" |findstr /v "DistinguishedName" | Sort-Object -Unique
$ADOrgUnit | Out-file -Append -FilePath $SaveLocation

$i = $i+1
$FileName=$i.ToString()+"_AD_Forest.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$ADForest = Get-ADForest
$ADForest | Out-File -Append -FilePath $SaveLocation

<#$i = $i+1
$FileName=$i.ToString()+"_AD_Adm_Users.txt"
$SaveLocation = $System_Stalker+"\"+$FileName
$ADAdmUser = Get-ADUser -Filter 'Name -like "*.adm"'
#>

#Compress $System_Stalker into a Zip_File
$source = $System_Stalker
$destination = $System_Stalker + ".zip"
Add-Type -AssemblyName "system.io.compression.filesystem"
[io.compression.zipfile]::CreateFromDirectory($source, $destination)

#Delete Folder Leaving Zip
Remove-Item $System_Stalker -Recurse

#X-fer Folder back to location



#delete zipped folder
#Remove-Item $destination

#Unabled to send via email, powershell does not have the exchange module installed.