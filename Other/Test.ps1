Clear-Host

. D:\Fabiano\Trabalho\Pythian\PowerShell\MAP_SQLServices\Get-SQLInstance.ps1

$Script = {Get-SQLInstance -ComputerName 'vmwin2012_1' -CheckServiceAndConnectivity 'N' }


Invoke-Command -ComputerName 'vmwin2012_1' -ScriptBlock $Script



