# Merlin Agent DLL
Merlin can be compiled into a DLL. The `data/bin/dll/merlin.c` file is
a very simple C file with a single function. The `VoidFunc` function is
an exported function required to execute the DLL.  The `VoidFunc` name
was specifically chosen to facilitate use with PowerSploit's
[Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
. Using `VoidFunc` requires no modification to run Merlin's DLL with
Invoke-ReflectivePEInjection.

It is recommended to compile the DLL on Windows.
The [TDM-GCC](http://tdm-gcc.tdragon.net/download) 64bit compiler has
proven to work well during testing.

## Limitations
It is important to note that the DLL is currently in the
Proof-of-Concept stage and will call back to the Merlin server at
127.0.0.1. Future work will facilitate specifying the value at compile
time or when executing the DLL.

One option to overcome this is to hard-code in the target Merlin server
address into the `url` variable of the `cmd/merlinagent/main.go` prior
to creating the C archive file.

## Creating the DLL
* Create the required C archive file:
  * `go build -buildmode=c-archive cmd\merlinagent\main.go`

* Compile the DLL
  * `gcc -shared -pthread -o data/bin/dll/merlin.dll data/bin/dll/merlin.c data/bin/dll/main.a -lWinMM -lntdll -lWS2_32`

You will now have DLL file that you can use with whatever method of
execution you would like.

An example of using `rundll32` is:

`rundll32 merlin.dll,main` or `rundll32 merlin.dll,VoidFunc`

## Invoke-Merlin
The compiled DLL can be inserted into the `Invoke-Merlin.ps1` script.
Check the [README](../powershell/README.MD) in the `powershell` directory for
additional details.