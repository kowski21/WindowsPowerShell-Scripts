# directory where my scripts are stored
function Reload-Env {
$psdir="C:\Users\c.kwiatkowski.adm\Documents\WindowsPowerShell\PScripts"  
# load all 'autoload' scripts
Get-ChildItem "${psdir}\*.ps1" | %{.$_} 
Write-Host "Custom PowerShell Environment Loaded" 
}
#$psdir is the location in which you're storing the functions you want to be called.