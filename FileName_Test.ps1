#Code Name: System_Stalker.ps1
#Global Save location; Modify as needed
$SaveLocation = $env:SystemDrive+"\Users\Charles.Kwiatkowski\Desktop\Dub_Test\"+$FileName
#starts in C:\Users so that it is able to pick up on userdata as opposed to the whole drive, unless need whole drive.
$ScanDir = $env:SystemDrive+"\Users\*"
$Starting = " Start collection of "
$H1 = " -------------------------------- "

#List Users:
$FileName="All_Users.txt"
$CreateList = Get-ChildItem -Path $ScanDir | Where-Object {$_.Name -like "*"} | Format-Table Fullname -AutoSize | where {$_ -ne ""}
$Heading = $H1 + $Starting + $FileName + $H1
$Heading | Out-File -Append -FilePath $SaveLocation
$CreateList | Out-File -Append -FilePath $SaveLocation