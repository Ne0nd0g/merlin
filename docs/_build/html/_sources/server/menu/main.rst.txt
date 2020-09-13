Main Menu
=========

help
----

After executing the Merlin server binary, interaction continues from the Merlin prompt ``Merlin»``. This is the default menu presented when starting the Merlin server. To view available commands for this menu, type `help` and press enter. Tab completion can be used at any time to provide the user a list of commands that can be selected.

| Merlin is equipped with a tab completion system that can be used to see what commands are available at any given time. Hit double tab to get a list of all available commands for the current menu context.

.. code-block:: text

    Merlin» help

       COMMAND  |          DESCRIPTION           |    OPTIONS
    +-----------+--------------------------------+----------------+
      agent     | Interact with agents or list   | interact, list
                | agents                         |
      banner    | Print the Merlin banner        |
      exit      | Exit and close the Merlin      |
                | server                         |
      listeners | Move to the listeners menu     |
      interact  | Interact with an agent. Alias  |
                | for Empire users               |
      quit      | Exit and close the Merlin      |
                | server                         |
      remove    | Remove or delete a DEAD agent
                | from the server
      sessions  | List all agents session        |
                | information. Alias for MSF     |
                | users                          |
      use       | Use a function of Merlin       | module
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
--------

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

exit
----

The ``exit`` command is used to quit the Merlin server. The user will be prompted for confirmation to prevent from accidentally quitting the program. The confirmation prompt can be skipped with ``exit -y``.

.. code-block:: text

    Merlin» exit

    Are you sure you want to exit? [yes/NO]:
    yes
    [!]Quitting...

listeners
---------

The ``listeners`` command will move into the Listeners menu.

interact
--------

The ``interact`` command takes one argument, the agent ID, and is used to interact with the specified agent. **NOTE:** Use the built-in tab completion to cycle through and select the agent to interact with.

.. code-block:: text

    Merlin» interact c22c435f-f7c4-445b-bcd4-0d4e020645af
    Merlin[agent][c22c435f-f7c4-445b-bcd4-0d4e020645af]»

quit
----

The ``quit`` command is an alias for the ``exit`` command and is used to quit the Merlin server. The user will be prompted for confirmation to prevent from accidentally quitting the program. The confirmation prompt can be skipped with ``quit -y``.

.. code-block:: text

    Merlin» quit

    Are you sure you want to exit? [yes/NO]:
    yes
    [!]Quitting...

remove
------

The ``remove`` command is used to remove or delete an agent from the server so that it will not show up in the list of available agents. **NOTE:** Removing an active agent will cause that agent to fail to check in and it will eventually exit.

.. code-block:: text

    Merlin» sessions

    +--------------------------------------+-------------+------+--------+-----------------+--------+
    |              AGENT GUID              |  PLATFORM   | USER |  HOST  |    TRANSPORT    | STATUS |
    +--------------------------------------+-------------+------+--------+-----------------+--------+
    | c62ac059-e54d-4204-82a4-d5c054b63ac3 | linux/amd64 | joe  | DEV001 | HTTP/2 over TLS |  Dead  |
    +--------------------------------------+-------------+------+--------+-----------------+--------+

    Merlin» remove c62ac059-e54d-4204-82a4-d5c054b63ac3
    Merlin»
    [i] Agent c62ac059-e54d-4204-82a4-d5c054b63ac3 was removed from the server at 2020-08-18T14:19:54Z
    Merlin» sessions

    +------------+----------+------+------+-----------+--------+
    | AGENT GUID | PLATFORM | USER | HOST | TRANSPORT | STATUS |
    +------------+----------+------+------+-----------+--------+
    +------------+----------+------+------+-----------+--------+

    Merlin»

sessions
--------

The ``sessions`` command is used to quickly list information about established agents from the main menu to include their status.

.. code-block:: text

    Merlin» sessions

    +--------------------------------------+-------------+------+--------+---------------------------+---------+
    |              AGENT GUID              |  PLATFORM   | USER |  HOST  |         TRANSPORT         | STATUS  |
    +--------------------------------------+-------------+------+--------+---------------------------+---------+
    | 6998f86a-f54b-4c90-a935-4620db5d2c4a | linux/amd64 | joe  | DEV001 |      HTTP/2 over TLS      | Active  |
    | 3b1fbded-1292-413f-81f6-edd8be260c25 | linux/amd64 | joe  | DEV001 | HTTP/3 (HTTP/2 over QUIC) | Active  |
    | 25c61141-6600-4c9a-abeb-f591494bf4c0 | linux/amd64 | joe  | DEV001 |     HTTP/2 clear-text     | Delayed |
    +--------------------------------------+-------------+------+--------+---------------------------+---------+

    Merlin»

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
