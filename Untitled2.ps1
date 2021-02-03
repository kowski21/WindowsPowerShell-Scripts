Invoke-Command -Credential $c -ComputerName $fqdn -ScriptBlock ${function:path-test}

$c = Get-Credential
$fqdn = "HQUWGEOCXMD0066"
$IP = "10.28.12.137"


#Kovitz's Machine
HQUWGEOCXMD0066 