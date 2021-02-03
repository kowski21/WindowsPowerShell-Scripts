#Code Name: System_Stalker.ps1
#Global Save location; Modify as needed
#starts in C:\Users so that it is able to pick up on userdata as opposed to the whole drive, unless need whole drive.
$ScanDir = $env:SystemDrive+"\Users\Charles.Kwiatkowski\*"
$i = 0

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
$SaveLocation = $env:SystemDrive+"\Users\Charles.Kwiatkowski\Desktop\Dub_Test\"+$FileName
$Search = Get-ChildItem -path $ScanDir -Recurse -Include $FileType | Sort-Object Name | Format-Table Fullname -AutoSize | where {$_ -ne ""}
$Search | Out-File -Append -FilePath $SaveLocation
#Increment variable
$i=$i+1
}
#Collect Users:
$f = $i+1
$FileName=$f.ToString()+"_All_Users.txt"
$SaveLocation = $env:SystemDrive+"\Users\Charles.Kwiatkowski\Desktop\Dub_Test\"+$FileName
$CreateList = Get-ChildItem -Path $ScanDir | Where-Object {$_.Name -like "*"} | Format-Table Fullname -AutoSize | where {$_ -ne ""}
$CreateList | Out-File -Append -FilePath $SaveLocation

<#
for($i=0;$i-le $FileTypes.Length-1;$i++)
{ 
if($i+1 -le 9)
{
$f = $i+1 
$FileName="0"+$f.ToString()+'_'+$FileTypes[$i].substring(2)+"_Files"
$FileName
}
Else 
{ 
$f = $i+1 
$FileName=$f.ToString()+'_'+$FileTypes[$i].substring(2)+"_Files"
$FileName
}
}
#>