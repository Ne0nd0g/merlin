Main Menu
=========

help
----

After executing the Merlin server binary, interaction continues from the Merlin prompt ``Merlin»``. This is the default menu presented when starting the Merlin server. To view available commands for this menu, type `help` and press enter. Tab completion can be used at any time to provide the user a list of commands that can be selected.

| Merlin is equipped with a tab completion system that can be used to see what commands are available at any given time. Hit double tab to get a list of all available commands for the current menu context.

.. code-block:: text

    Merlin» help

       COMMAND  |          DESCRIPTION           |            OPTIONS
    +-----------+--------------------------------+--------------------------------+
      agent     | Interact with agents or list   | interact, list
                | agents                         |
      banner    | Print the Merlin banner        |
      clear     | clears all unset jobs          |
      group     | Add, remove, or list groups    | group <add | remove | list>
                |                                | <group>
      interact  | Interact with an agent         |
      jobs      | Display all unfinished jobs    |
      listeners | Move to the listeners menu     |
      queue     | queue up commands for one, a   | queue <agentID> <command>
                | group, or unknown agents       |
      quit      | Exit and close the Merlin      | -y
                | server                         |
      remove    | Remove or delete a DEAD agent
                | from the server
      sessions  | Display a table of information |
                | about all checked-in agent     |
                | sessions                       |
      use       | Use a Merlin module            | module <module path>
      version   | Print the Merlin server        |
                | version                        |
      *         | Anything else will be execute  |
                | on the host operating system   |
    Main Menu Help

agent
-----

The ``agent`` command is used to interact with Merlin Agents. In most cases, the ``agent`` command is followed by a sub-command and then the agent's identifier. The agent identifiers are UUID version 4 strings. *The identifiers are long, but they can easily be filled in using Merlin's tab completion*. This ensures limited typing is required.

Available agent sub-command are:
* [list](#list)
* [interact](#interact)

list
^^^^

The ``list`` option for the agent command is used to provide a list of all the available agents.

.. code-block:: text

    Merlin» agent list

    +--------------------------------------+---------------+-----------------+-----------+-----------+
    |              AGENT GUID              |   PLATFORM    |      USER       |   HOST    | TRANSPORT |
    +--------------------------------------+---------------+-----------------+-----------+-----------+
    | 54a20389-4f8a-4e3f-9f8e-a0f686ce529e |  linux/amd64  |     root        | kali      |  HTTP/2   |
    | c1090dbc-f2f7-4d90-a241-86e0c0217786 | windows/amd64 |   ACME\Dade     | WIN-7PD32 |  HTTP/2   |
    | 6af7d4a1-170f-43b7-a107-758f7855e6ba | darwin/amd64  |   nikon         | nikon-mac |  HTTP/2   |
    +--------------------------------------+---------------+-----------------+-----------+-----------+


interact
^^^^^^^^

The ``interact`` option for the agent command is used to switch an agent context menu to interact with a single agent. This will cause the prompt to change indicating the agent you are interacting with and provide a new menu of commands.

.. code-block:: text

    Merlin» agent interact 54a20389-4f8a-4e3f-9f8e-a0f686ce529e
    Merlin[agent][54a20389-4f8a-4e3f-9f8e-a0f686ce529e]»

banner
------

The ``banner`` command is used too print the super cool ascii art banner along with the version and build numbers.

.. code-block:: text

    Merlin» banner
    Merlin»


                                   &&&&&&&&
                                 &&&&&&&&&&&&
                                &&&&&&&&&&&&&&&
                              &&&&&&&&&&& &&&&
                             &&&&&&&&&&&&&  &&&&
                            &&&&&&&&&&&& &  &&&&
                           &&&&&&&&&&&&&     &&&&
                          &&&&&&&&&&&&&&&     &&&
                         &&&&&&&&&&&&&&&&&     &&&
                        &&&&&&&&&&&&&&&&&&&     &&&
                       &&&&&&&&&&&&&&&&&&&&&
                      &&&&&&&&&&&&&&&&&&&&&&&
                      &&&&&&&&&&&&&&&&&&&&&&&
                     &&&&&&&&&&&&&&&&&&&&&&&&&
                    &&&&&&&&&&&&&&&&&&&&&&&&&&&
                   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&
                  &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
                 &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
           &&&&  &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&   &&&
        &&&&&&  &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&&&&&
      &&&&&&&   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&   &&&&&&&
    &&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&&&&&&&&
    &&&&&&&&&&  &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  &&&&&&&&&&
    &&&&&&&&&&&   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&   &&&&&&&&&&&
    &&&&&&&&&&&&&     &&&&&&&&&&&&&&&&&&&&&&&     &&&&&&&&&&&&&
      &&&&&&&&&&&&&&&          MERLIN         &&&&&&&&&&&&&&&
        &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
           &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
               &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
                       Version: 0.8.0.BETA
                       Build: nonRelease

clear
-----

The ``clear`` command will cancel all jobs in the queue that have not been sent to the agent yet.
This command will only clear jobs for ALL agents.

.. code-block:: text

    Merlin» clear
    Merlin»
    [+] All unsent jobs cleared at 2021-08-03T01:10:09Z

group
-----

The ``group`` command interacts with server-side groups that agents can be added to and removed from.
Arbitrary agent commands and modules can be executed against an entire group at one time.

* :ref:`group add`
* :ref:`group list`
* :ref:`group remove`

.. _group add:

add
^^^

The ``group add`` command adds an agent to a named group. If the group name does not exist, it will be created.
The list of available agents can be tab completed.

``group add <agentID> <GroupName>``

.. code-block:: text

    Merlin» group add 99dbe632-984c-4c98-8f38-11535cb5d937 EvilCorp

    [i] Agent 99dbe632-984c-4c98-8f38-11535cb5d937 added to group EvilCorp

    Merlin» group add d07edfda-e119-4be2-a20f-918ab701fa3c EvilCorp

    [i] Agent d07edfda-e119-4be2-a20f-918ab701fa3c added to group EvilCorp

.. _group list:

list
^^^^

The ``group list`` command displays all existing group names to include agents that are members of a group.
The ``all`` group always exists and is used to task every known agent.

.. code-block:: text

    Merlin» group list
    +----------+--------------------------------------+
    |  GROUP   |               AGENT ID               |
    +----------+--------------------------------------+
    | all      | ffffffff-ffff-ffff-ffff-ffffffffffff |
    | EvilCorp | 99dbe632-984c-4c98-8f38-11535cb5d937 |
    | EvilCorp | d07edfda-e119-4be2-a20f-918ab701fa3c |
    +----------+--------------------------------------+

.. _group remove:

remove
^^^^^^

The ``group remove`` command is used to remove an agent from a named group. The list of ALL agents is tab completable
but does not mean the agent is in the group. The list of existing groups can also be tab completed.

``group remove <agentID> <GroupName>``

.. code-block:: text

    Merlin» group remove 99dbe632-984c-4c98-8f38-11535cb5d937 EvilCorp
    Merlin»
    [i] Agent 99dbe632-984c-4c98-8f38-11535cb5d937 removed from group EvilCorp

interact
--------

The ``interact`` command takes one argument, the agent ID, and is used to interact with the specified agent. **NOTE:** Use the built-in tab completion to cycle through and select the agent to interact with.

.. code-block:: text

    Merlin» interact c22c435f-f7c4-445b-bcd4-0d4e020645af
    Merlin[agent][c22c435f-f7c4-445b-bcd4-0d4e020645af]»

jobs
----

The ``jobs`` command displays unfinished jobs for ALL agents.

.. code-block:: text

    Merlin» jobs

                     AGENT                 |     ID     |  COMMAND   | STATUS  |       CREATED        |         SENT
    +--------------------------------------+------------+------------+---------+----------------------+----------------------+
      d07edfda-e119-4be2-a20f-918ab701fa3c | UjNoTALgcn | pwd        | Created | 2021-08-03T01:39:57Z |
      99dbe632-984c-4c98-8f38-11535cb5d937 | UHOddpFQTm | run whoami | Sent    | 2021-08-03T01:40:11Z | 2021-08-03T01:40:17Z

queue
-----

The ``queue`` command can be used to pre-load, or queue, arbitrary commands/jobs against an agent or a group.
Additionally, the agent does not have to exist for this command to be used.
When an agent with that ID checks in, it will receive the job.

Queue a command for one agent:

.. code-block:: text

    Merlin» queue 99dbe632-984c-4c98-8f38-11535cb5d937 run ping 8.8.8.8
    [-] Created job LumWveIkKe for agent 99dbe632-984c-4c98-8f38-11535cb5d937
    [-] Results job LumWveIkKe for agent 99dbe632-984c-4c98-8f38-11535cb5d937

    [+]
    Pinging 8.8.8.8 with 32 bytes of data:
    Reply from 8.8.8.8: bytes=32 time=42ms TTL=128
    Reply from 8.8.8.8: bytes=32 time=63ms TTL=128
    Reply from 8.8.8.8: bytes=32 time=35ms TTL=128
    Reply from 8.8.8.8: bytes=32 time=48ms TTL=128

    Ping statistics for 8.8.8.8:
        Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 35ms, Maximum = 63ms, Average = 47ms

Queue a command for a group:

.. code-block:: text

    Merlin» queue EvilCorp run whoami

    [-] Created job lkvozuKJLW for agent d07edfda-e119-4be2-a20f-918ab701fa3c

    [-] Created job xKAgunnKTF for agent 99dbe632-984c-4c98-8f38-11535cb5d937
    Merlin»
    [-] Results job xKAgunnKTF for agent 99dbe632-984c-4c98-8f38-11535cb5d937

    [+] DESKTOP-H39FR21\bob


    [-] Results job lkvozuKJLW for agent d07edfda-e119-4be2-a20f-918ab701fa3c

    [+] rastley

Queue a command for an agent that has never checked in before and is currently unknown to the server:

.. code-block:: text

    Merlin» queue c1090dbc-f2f7-4d90-a241-86e0c0217786 run whoami
    [-] Created job rJVyZTuHkm for agent c1090dbc-f2f7-4d90-a241-86e0c0217786

.. warning::
    Some agent control commands such as ``sleep`` can not be queued because the agent structure must exist on the server to calculate the JWT

listeners
---------

The ``listeners`` command will move into the Listeners menu.

.. code-block:: text

    Merlin» listeners
    Merlin[listeners]»

quit
----

The ``quit`` command is used to stop and exit the Merlin server. The user will be prompted for confirmation to prevent
from accidentally quitting the program. The confirmation prompt can be skipped with ``quit -y``.

.. code-block:: text

    Merlin» quit

    Are you sure you want to exit? [yes/NO]:
    yes
    [!]Quitting...

remove
------

The ``remove`` command is used to remove or delete an agent from the server so that it will not show up in the list of available agents.

.. note::
    Removing an active agent will cause that agent to fail to check in and it will eventually exit.

.. code-block:: text

    Merlin» sessions

    +--------------------------------------+-------------+------+--------+-----------------+--------+
    |              AGENT GUID              |  PLATFORM   | USER |  HOST  |    TRANSPORT    | STATUS |
    +--------------------------------------+-------------+------+--------+-----------------+--------+
    | c62ac059-e54d-4204-82a4-d5c054b63ac3 | linux/amd64 | joe  | DEV001 | HTTP/2 over TLS |  Dead  |
    +--------------------------------------+-------------+------+--------+-----------------+--------+

    Merlin» remove c62ac059-e54d-4204-82a4-d5c054b63ac3
    Merlin»
    [i] Agent c62ac059-e54d-4204-82a4-d5c054b63ac3 was removed from the server
    Merlin» sessions

    +------------+----------+------+------+-----------+--------+
    | AGENT GUID | PLATFORM | USER | HOST | TRANSPORT | STATUS |
    +------------+----------+------+------+-----------+--------+
    +------------+----------+------+------+-----------+--------+

    Merlin»

sessions
--------

The ``sessions`` command is used to quickly list information about established agents from the main menu to include their status.
The sessions command is available from any menu in the CLI.

* **AGENT GUID**: A unique identifier for every running instance
* **TRANSPORT**: The protocol the agent is communicating over
* **PLATFORM**: The operating system and architecture the agent is running on
* **HOST**: The hostname where the agent is running
* **USER**: The username that hte agent is running as
* **PROCESS**: The Agent's process name followed by its Process ID (PID) in parenthesis
* **STATUS**: The Agent's communiction status of either active, delayed, or dead
* **LAST CHECKIN**: The amount of time that has passed since the agent last checked in
* **NOTE**: A free-form text area for operators to record notes about a specific agent; tracked server-side only

.. code-block:: text

    Merlin» sessions

                   AGENT GUID              |    TRANSPORT    |   PLATFORM    |      HOST       |        USER         |                 PROCESS                  | STATUS | LAST CHECKIN |      NOTE
    +--------------------------------------+-----------------+---------------+-----------------+---------------------+------------------------------------------+--------+--------------+-----------------+
      d07edfda-e119-4be2-a20f-918ab701fa3c | HTTP/2 over TLS | linux/amd64   | ubuntu          | rastley             | main(200769)                             | Active | 0:00:08 ago  | Demo Agent Here

use
---

The ``use`` command is leveraged to access a feature such as modules. Currently there is only one option and that is ``use modules`` to access Merlin modules. View the modules page for additional details.

version
-------

The ``version`` command is used to simply print the version numbers of the running Merlin server.

.. code-block:: text

    Merlin» version

    Merlin version: 0.8.0.BETA

    Merlin»

wildcard
--------

Any command that is not a Merlin command will be executed on host itself where the Merlin server is running. This is useful when you want simple information, such as your interface address, without having to open a new terminal.

.. code-block:: text

    Merlin» ip a show ens32

    [i] Executing system command...

    [+] 2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 00:0c:29:z3:ff:91 brd ff:ff:ff:ff:ff:ff
        inet 192.168.211.221/24 brd 192.168.211.255 scope global dynamic noprefixroute ens32
           valid_lft 1227sec preferred_lft 1227sec
        inet6 fe80::a71d:1f6a:a0d1:7985/64 scope link noprefixroute
           valid_lft forever preferred_lft forever

    Merlin»
