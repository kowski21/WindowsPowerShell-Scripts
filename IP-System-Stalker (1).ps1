function IP-System-Stalker ($IPList, $SaveLocationIP)
{
foreach ($IP in $IPList)
{
#Code Name: System_Stalker.ps1
#get system drive letter
$DriveLetter = $env:SystemDrive.Split("{:}") | where {$_ -ne ""}

#Global Save location; Modify as needed
$SaveLocation = "\\"+$SaveLocationIP+"\"+$DriveLetter+"$\Users\Charles.Kwiatkowski\Desktop\Info.txt"
#starts in C:\Users so that it is able to pick up on userdata as opposed to the whole drive, unless need whole drive.

$ScanDir = "\\"+$IP+"\"+$DriveLetter+"$\Users\*"
$Starting = " Start collection of "
$H1 = " -------------------------------- "

#List Users:
$CreateList = Get-ChildItem -Path $ScanDir | Where-Object {$_.Name -like "*"} | Format-Table Fullname | where {$_ -ne ""}
$Heading = $H1 + $Starting + " All Users " + $H1
$Heading | Out-File -Append -FilePath $SaveLocation
$CreateList | Out-File -Append -FilePath $SaveLocation

#List Users whos name appears as *.adm:
$CreateList = Get-ChildItem -Path $ScanDir | Where-Object {$_.Name -like "*.adm"} | Format-Table Fullname | where {$_ -ne ""}
$Heading = $H1 + $Starting + " List Users whos name appears as *.adm " + $H1
$Heading | Out-File -Append -FilePath $SaveLocation
$CreateList | Out-File -Append -FilePath $SaveLocation

#Pull File Types:
#File Types are those you want to look for. Modify as needed
#--- ORIGINAL Do not Touch --- $FileTypes = "*.pdf,*.txt,*.doc,*.docx,*.xls,*.xlsx,*.jpg,*.jpeg,*.gif,*.bmp" --- ORIGINAL Do not Touch ---
$FileTypes = "*.pdf,*.txt,*.doc,*.docx,*.xls,*.xlsx,*.jpg,*.jpeg,*.gif,*.bmp,*.exe,*.zip,*.7z"
#Iterate through the list of FileTypes
foreach ($FileType in $FileTypes)
{
$Heading = $H1 + $Starting + $FileType + "'s " + $H1
$Heading | Out-File -Append -FilePath $SaveLocation
$Search = Get-ChildItem -path $ScanDir -Recurse -Include $FileType | Sort-Object Name | Format-Table Fullname -auto | Out-String -Width 1024 | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation
}

$Heading = $H1 + $Starting + "Collection of Prefetch Data" + $H1 | where {$_ -ne ""}
$Heading | Out-File -Append -FilePath $SaveLocation
$Search = Get-ChildItem -path $DriveLetter\Windows\prefetch | Sort-Object Name | Format-Table Fullname -auto | Out-String -Width 1024 | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation

$Heading = $H1 + $Starting + "Collection of Mof Files from System32\wbem" + $H1
$Heading | Out-File -Append -FilePath $SaveLocation
$Search = Get-ChildItem -path $DriveLetter\Windows\System32\wbem -Recurse -Include "*.mof" | Sort-Object Name | Format-Table Fullname -auto | Out-String -Width 1024 | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation

#Gather IP Information
$Heading = $H1 + $Starting + "ipconfig /all" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$IPInfo = ipconfig /all | where {$_ -ne ""}
$IPInfo | Out-File -Append -FilePath $SaveLocation

#Gather Systeminfo
$Heading = $H1 + $Starting + "Systeminfo without hotfixes" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$SystemInfo = systeminfo | findstr /v "KB" | where {$_ -ne ""}
$SystemInfo | Out-file -Append -FilePath $SaveLocation

#Gather Group Policy Results
$Heading = $H1 + $Starting + "gpresult /R" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$GPResult = gpresult /R | where {$_ -ne ""}
$GPResult | Out-file -Append -FilePath $SaveLocation

#Gather Group Policy Users
$Heading = $H1 + $Starting + "gpresult /Scope User /v" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$GPResultUser = gpresult /Scope User /Z | where {$_ -ne ""}
$GPResultUser | Out-file -Append -FilePath $SaveLocation

#Gather Group Policy Computers
$Heading = $H1 + $Starting + "gpresult /Scope Computer /v" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$GPResultComp = gpresult /Scope Computer /Z | where {$_ -ne ""}
$GPResultComp | Out-file -Append -FilePath $SaveLocation

#Gather Net Share
$Heading = $H1 + $Starting + "net share" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetShare = net share | findstr /v " -" | findstr /v "The " | where {$_ -ne ""}
$NetShare | Out-file -Append -FilePath $SaveLocation

#Gather Net User
$Heading = $H1 + $Starting + "net user" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetUser = net user | findstr /v " -" | findstr /v "The " | where {$_ -ne ""} 
$NetUser | Out-file -Append -FilePath $SaveLocation

#Gather Net Local Group
$Heading = $H1 + $Starting + "net localgroup" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetLocalGroup = net localgroup | findstr /v " -" | findstr /v "The " | where {$_ -ne ""}
$NetLocalGroup | Out-file -Append -FilePath $SaveLocation

#Gather Net Accounts
$Heading = $H1 + $Starting + "net accounts" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetAccounts = net accounts | findstr /v "The " | where {$_ -ne ""}
$NetAccounts | Out-file -Append -FilePath $SaveLocation

#Gather Net Accounts Domain
$Heading = $H1 + $Starting + "net accoutns /domain" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetAccountsDomain = net accounts /domain | findstr /v "The " | where {$_ -ne ""}
$NetAccountsDomain | Out-file -Append -FilePath $SaveLocation

#Gather Net config workstation
$Heading = $H1 + $Starting + "net accoutns /domain" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetAccountsDomain = net config workstation | findstr /v "The " | where {$_ -ne ""} <#Server for servers#> 
$NetAccountsDomain | Out-file -Append -FilePath $SaveLocation

#Gather Net file
$Heading = $H1 + $Starting + "Net file" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetFile = net file | where {$_ -ne ""}
$NetFile | Out-file -Append -FilePath $SaveLocation

#Gather Driver Data
$Heading = $H1 + $Starting + "Driver Query /v" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$DriverQueryV = driverquery /v /FO CSV | ConvertFrom-Csv | findstr /v "Init(bytes)" | findstr /v "Code(bytes)" | findstr /v "Paged Pool(bytes)" | findstr /v "BSS(bytes)" | findstr /v "Description" | findstr /v "State" | findstr /v "Status" | findstr /v "Accept"
$DriverQueryV | Out-File -Append -FilePath $SaveLocation

#Gather Signed Info
$Heading = $H1 + $Starting + "Driver Query /si" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$DriverQuerySI = driverquery /si /FO CSV | ConvertFrom-Csv | Format-Table -AutoSize
$DriverQuerySI | Out-file -Append -FilePath $SaveLocation

#Gather Netstat Info
$Heading = $H1 + $Starting + "netstat -anop tcp" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetstatANOP = netstat -anop tcp | findstr /v "127.0.0.1" | findstr /v "0.0.0.0" | where {$_ -ne ""}
$NetstatANOP | Out-file -Append -FilePath $SaveLocation

#Gather More netstat Info
$Heading = $H1 + $Starting + "netstat -anob" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetstatANOB = netstat -anob | where {$_ -ne ""}
$NetstatANOB | Out-file -Append -FilePath $SaveLocation

#Gather Tasklisting
$Heading = $H1 + $Starting + "tasklist" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$TaskList = tasklist | where {$_ -ne ""}
$TaskList | Out-file -Append -FilePath $SaveLocation

#Reg Queries

$Heading = $H1 + $Starting + "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$HKLMRun = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s | where {$_ -ne ""}
$HKLMRun | Out-file -Append -FilePath $SaveLocation

$Heading = $H1 + $Starting + "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /s" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$HKLMRunOnce = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | where {$_ -ne ""}
$HKLMRunOnce | Out-file -Append -FilePath $SaveLocation

$Heading = $H1 + $Starting + "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$HKCURun = reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s | where {$_ -ne ""}
$HKCURun | Out-file -Append -FilePath $SaveLocation

$Heading = $H1 + $Starting + "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /s" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$HKCURunOnce = reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | where {$_ -ne ""}
$HKCURunOnce | Out-file -Append -FilePath $SaveLocation

$Heading = $H1 + $Starting + "reg query HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run /s" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$HKURun = reg query HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run /s
$HKURun | Out-file -Append -FilePath $SaveLocation

#Netsh Infromation Gathering

#Gather Netsh advfirewall firewall show rule name=all (Only Names)
$Heading = $H1 + $Starting + "Netsh advfirewall firewall show rule name=all (Only Names)" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$AdvFirewallRuleNames = Netsh advfirewall firewall show rule name=all | findstr "Rule Name:" | Sort-Object -Unique | where {$_ -ne ""}
$AdvFirewallRuleNames | Out-file -Append -FilePath $SaveLocation

<# Disabled unless needed to pull rule information
#Gather Netsh advfirewall firewall show rule name=all
$Heading = $H1 + $Starting + "Netsh advfirewall firewall show rule name=all" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$AdvFirewallRules = Netsh advfirewall firewall show rule name=all  
$AdvFirewallRules | Out-file -Append -FilePath $SaveLocation
#>

#Gather Netsh ipsec dynamic show all
$Heading = $H1 + $Starting + "Netsh ipsec dynamic show all" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$IpSecDynamic = netsh ipsec dynamic show all | where {$_ -ne ""}
$IpSecDynamic | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ipsec static show all
$Heading = $H1 + $Starting + "Netsh ipsec static show all" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$IpSecStatic = netsh ipsec static show all | where {$_ -ne ""}
$IpSecStatic | Out-file -Append -FilePath $SaveLocation

#Gather Netsh lan show interfaces
$Heading = $H1 + $Starting + "Netsh lan show interfaces" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$LanInt = netsh lan show interfaces | where {$_ -ne ""}
$LanInt | Out-file -Append -FilePath $SaveLocation

#Gather Netsh lan show profiles
$Heading = $H1 + $Starting + "Netsh lan show profiles" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$LanProfiles = netsh lan show profiles | where {$_ -ne ""}
$LanProfiles | Out-file -Append -FilePath $SaveLocation

#Gather Netsh lan show settings
$Heading = $H1 + $Starting + "Netsh lan show settings" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$LanSettings = netsh lan show settings | where {$_ -ne ""}
$LanSettings | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ras show authmode
$Heading = $H1 + $Starting + "Netsh ras show authmode" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$RasAuthMode = netsh ras show authmode | where {$_ -ne ""}
$RasAuthMode | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ras show authtype
$Heading = $H1 + $Starting + "Netsh ras show authtype" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$RasAuthType = netsh ras show authtype | where {$_ -ne ""}
$RasAuthType | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ras show sstp-ssl-cert
$Heading = $H1 + $Starting + "Netsh ras show sstp-ssl-cert" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$RasSSTP = netsh ras show sstp-ssl-cert | where {$_ -ne ""}
$RasSSTP | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ras ip show config
$Heading = $H1 + $Starting + "Netsh ras ip show config" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$RasConfig = netsh ras ip show config | where {$_ -ne ""}
$RasConfig | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ras ip show preferredadapter
$Heading = $H1 + $Starting + "Netsh ras ip show preferredadapter" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$RasPrefAdapter = netsh ras ip show preferredadapter | where {$_ -ne ""}
$RasPrefAdapter | Out-file -Append -FilePath $SaveLocation

#Gather Netsh ras ipv6 show config
$Heading = $H1 + $Starting + "Netsh ras ipv6 show config" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$RasIPv6Config = netsh ras ipv6 show config | where {$_ -ne ""}
$RasIPv6Config | Out-file -Append -FilePath $SaveLocation

#Gather Netsh wlan show all
$Heading = $H1 + $Starting + "Netsh wlan show all" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WlanAll = netsh wlan show all | where {$_ -ne ""}
$WlanAll | Out-file -Append -FilePath $SaveLocation

#Gather Netstat -ab
$Heading = $H1 + $Starting + "Netstat -ab" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetStatAB = netstat -ab | where {$_ -ne ""}
$NetStatAB | Out-file -Append -FilePath $SaveLocation

#Gather Netstat -aon
$Heading = $H1 + $Starting + "Netstat -aon" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$NetStatAON = netstat -aon | findstr /v "*:*" | findstr /v ":0" | findstr /v "127.0.0.1" | where {$_ -ne ""}
$NetStatAON | Out-file -Append -FilePath $SaveLocation

#Gather Query session
$Heading = $H1 + $Starting + "Query session" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$QuerySession = query session | where {$_ -ne ""}
$QuerySession | Out-file -Append -FilePath $SaveLocation

#Gather Query User
$Heading = $H1 + $Starting + "Query user" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$QueryUser = query user | where {$_ -ne ""}
$QueryUser | Out-file -Append -FilePath $SaveLocation

#Gather Query process
$Heading = $H1 + $Starting + "Query process" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$QueryProcess = query process | where {$_ -ne ""}
$QueryProcess | Out-file -Append -FilePath $SaveLocation

#Gather Wmic startup
$Heading = $H1 + $Starting + "Wmic startup" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicStartup = wmic startup get "Caption,Command,Location,User,UserSID" | where {$_ -ne ""}
$WmicStartup | Out-file -Append -FilePath $SaveLocation

#Gather Wmic sysaccount
$Heading = $H1 + $Starting + "Wmic sysaccount" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicSysAccount = wmic sysaccount get "Caption,Description,Domain,LocalAccount,Name,SID,SIDType,Status" | where {$_ -ne ""}
$WmicSysAccount | Out-file -Append -FilePath $SaveLocation

#Gather Wmic dcomapp
$Heading = $H1 + $Starting + "Wmic dcomapp" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicDcomApp = wmic dcomapp get "AppID,Name" | where {$_ -ne ""}
$WmicDcomApp | Out-file -Append -FilePath $SaveLocation

#Gather Wmic csproduct
$Heading = $H1 + $Starting + "Wmic csproduct" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicCsProduct = wmic csproduct get "Caption,IdentifyingNumber,Name,UUID,Vendor" | where {$_ -ne ""}
$WmicCsProduct | Out-file -Append -FilePath $SaveLocation

#Gather Wmic environment
$Heading = $H1 + $Starting + "Wmic environment" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicEnv = wmic environment get "Caption,Description,Name,SystemVariable,UserName,VariableValue" | where {$_ -ne ""}
$WmicEnv | Out-file -Append -FilePath $SaveLocation

#Gather Wmic group
$Heading = $H1 + $Starting + "Wmic group" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicGroup = wmic group get "Caption,Description,Domain,LocalAccount,Name,SID,SIDType,Status" | where {$_ -ne ""}
$WmicGroup | Out-file -Append -FilePath $SaveLocation

#Gather Wmic logicaldisk
$Heading = $H1 + $Starting + "Wmic logicaldisk" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicLogicalDisk = wmic logicaldisk get "Name,Compressed,CreationClassName,Description,DriveType,FileSystem" | where {$_ -ne ""}
$WmicLogicalDisk | Out-file -Append -FilePath $SaveLocation

#Gather Wmic nic
$Heading = $H1 + $Starting + "Wmic nic" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicNic = wmic nic get "Name,Description,Manufacturer,MACAddress,NetConnectionID,NetEnabled,NetworkAddresses,PermanentAddress,PNPDeviceID,ProductName,ServiceName" | where {$_ -ne ""}
$WmicNic | Out-file -Append -FilePath $SaveLocation

#Gather Wmic nicconfig
$Heading = $H1 + $Starting + "Wmic nicconfig" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicNicConfig = wmic nicconfig get "Description,DatabasePath,DefaultIPGateway,DHCPServer,DNSDomain,DNSDomainSuffixSearchOrder,DNSHostName,DNSServerSearchOrder,IPAddress,IPSubnet,ServiceName" | where {$_ -ne ""}
$WmicNicConfig | Out-file -Append -FilePath $SaveLocation

#Gather Wmic ntdomain
$Heading = $H1 + $Starting + "Wmic ntdomain" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicNTDomain = wmic ntdomain | where {$_ -ne ""}
$WmicNTDomain | Out-file -Append -FilePath $SaveLocation

#Gather Wmic os
$Heading = $H1 + $Starting + "Wmic os" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicOS = wmic os get "Name,Caption,Version,MUILanguages,OSArchitecture,RegisteredUser" | where {$_ -ne ""}
$WmicOS | Out-file -Append -FilePath $SaveLocation

#Gather Wmic partition
$Heading = $H1 + $Starting + "Wmic partition" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicPartition = wmic partition get "Caption,DeviceID,Description,PrimaryPartition,SystemName" | where {$_ -ne ""}
$WmicPartition | Out-file -Append -FilePath $SaveLocation

#Gather wmic printerconfig
$Heading = $H1 + $Starting + "wmic printerconfig" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicPrinterConf = wmic printerconfig get "DeviceName,DriverVersion" | where {$_ -ne ""}
$WmicPrinterConf | Out-file -Append -FilePath $SaveLocation

#Gather wmic printer
$Heading = $H1 + $Starting + "wmic printer" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicPrinter = wmic printer get "Caption,CreationClassName" | where {$_ -ne ""}
$WmicPrinter | Out-file -Append -FilePath $SaveLocation

#Gather wmic process
$Heading = $H1 + $Starting + "wmic process" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicProcess = wmic process get "Name,Caption,CommandLine,WindowsVersion,CSName,Description,ExecutablePath,OSName" | where {$_ -ne ""}
$WmicProcess | Out-file -Append -FilePath $SaveLocation

#Gather wmic product get
$Heading = $H1 + $Starting + "wmic product get" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicProduct = wmic product get "Caption,Description,Version,InstallLocation,LocalPackage,Name,PackageName" | where {$_ -ne ""}
$WmicProduct | Out-file -Append -FilePath $SaveLocation

#Gather wmic softwarefeature get
$Heading = $H1 + $Starting + "wmic softwarefeature get" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicSoftFeature = wmic softwarefeature get "Name,Version,Caption,Description" | where {$_ -ne ""}
$WmicSoftFeature | Out-file -Append -FilePath $SaveLocation

#Gather wmic rdnic
$Heading = $H1 + $Starting + "wmic rdnic" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicRdNic = wmic rdnic get "TerminalName,NetworkAdapterName,NetworkAdapterList,DeviceIDList" | where {$_ -ne ""}
$WmicRdNic | Out-file -Append -FilePath $SaveLocation

#Gather wmic rdaccount
$Heading = $H1 + $Starting + "wmic rdaccount" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicRdAccount = wmic rdaccount get "AccountName,SID,TerminalName" | where {$_ -ne ""}
$WmicRdAccount | Out-file -Append -FilePath $SaveLocation

#Gather wmic rdpermissions
$Heading = $H1 + $Starting + "wmic rdpermissions" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$WmicRdPermissions = wmic rdpermissions | where {$_ -ne ""}
$WmicRdPermissions | Out-file -Append -FilePath $SaveLocation

#Gather schtasks
$Heading = $H1 + $Starting + "schtasks" + $H1
$Heading | Out-file -Append -FilePath $SaveLocation
$SchTasks = schtasks | where {$_ -ne ""}
$SchTasks | Out-file -Append -FilePath $SaveLocation
}}

