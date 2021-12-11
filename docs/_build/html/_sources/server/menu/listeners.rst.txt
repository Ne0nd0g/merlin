#############
Listener Menu
#############

Main
====

help
----

The ``help`` command is used to view available commands for the Listener menu. Tab completion can be used at any time to provide the user a list of commands that can be selected.

| Merlin is equipped with a tab completion system that can be used to see what commands are available at any given time. Hit double tab to get a list of all available commands for the current menu context.

.. code-block:: text

       COMMAND  |          DESCRIPTION           |            OPTIONS
    +-----------+--------------------------------+--------------------------------+
      back      | Return to the main menu        |
      configure | Interact with and configure a  | configure <listener_name>
                | named listener to modify it    |
      delete    | Delete a named listener        | delete <listener_name>
      info      | Display all information about  | info <listener_name>
                | a listener                     |
      interact  | Interact with an agent         | interact <agent_id>
      list      | List all created listeners     |
      main      | Return to the main menu        |
      sessions  | List all agents session        |
                | information. Alias for MSF     |
                | users                          |
      start     | Start a named listener         | start <listener_name>
      stop      | Stop a named listener          | stop <listener_name>
      use       | Create a new listener by       | use
                | protocol type                  | [http,https,http2,http3,h2c]
      !         | Execute a command on the host  | !<command> <args>
                | operating system               |

back
----

The ``back`` command is used to move one level back. In this case the command will return the user to the :doc:`main`.

.. code-block:: html

    Merlin[listeners]» back
    Merlin»

configure
---------

The ``configure`` command is used to operate, or configure, a previously created listener.

**NOTE:** Cycle through the available listeners using the tab key after the info command.

.. code-block:: text

    Merlin[listeners]» configure Default
    Merlin[listeners][Default]»

delete
------

The ``delete`` command is used to delete a listener by its name. The user will be prompted for confirmation to prevent accidentally deleting a listener.

**NOTE:** Cycle through the available listeners using the tab key after the delete command.

.. code-block:: html

    Merlin[listeners]» delete Default

    Are you sure you want to delete the Default listener? [yes/NO]:
    yes
    Merlin[listeners]»
    [+] deleted listener Default:0db5969e-2fa5-4f6d-8ec8-e07eaf4bf2c2
    Merlin[listeners]»

info
----

The ``info`` command is used to display information about a previously created Listener.

.. Note::
    Cycle through the available listeners using the tab key after the info command.

* **Protocol**: The communication protocol the listener will use
* **Name**: The operator defined name for the listener
* **Port**: The port that the listener will bind to
* **PSK**: The Pre-Shared Key (PSK) that the listener will use for initial communication with an agent
* **URLS**: The URLs that the listener will answer on for agent communications
* **X509Cert**: The file path to the SSL/TLS x509 public certificate the listener will use
* **X509Key**: The file path to the SSL/TLS x509 key file the listener will use
* **Description**: The operator defined description of the listener
* **ID**: A unique identifier for the instantiated listener
* **Interface**: The network interface that the listener will bind to. Use ``0.0.0.0`` for ALL interfaces

.. code-block:: html

    Merlin[listeners]» info Default
    +-------------+-----------------------------------------------------------------+
    |    NAME     |                              VALUE                              |
    +-------------+-----------------------------------------------------------------+
    | Protocol    | HTTPS                                                           |
    +-------------+-----------------------------------------------------------------+
    | Name        | Default                                                         |
    +-------------+-----------------------------------------------------------------+
    | Port        | 443                                                             |
    +-------------+-----------------------------------------------------------------+
    | PSK         | merlin                                                          |
    +-------------+-----------------------------------------------------------------+
    | URLS        | /                                                               |
    +-------------+-----------------------------------------------------------------+
    | X509Cert    |                                                                 |
    +-------------+-----------------------------------------------------------------+
    | X509Key     |                                                                 |
    +-------------+-----------------------------------------------------------------+
    | Description | Default listener                                                |
    +-------------+-----------------------------------------------------------------+
    | ID          | aa020d5c-7c1a-4781-9d1d-e7c659d126f9                            |
    +-------------+-----------------------------------------------------------------+
    | Interface   | 127.0.0.1                                                       |
    +-------------+-----------------------------------------------------------------+

.. _listener interact:

interact
--------

The ``interact`` command takes one argument, the agent ID, and is used to switch agents and interact with a different, specified agent.

.. note::
    Use the built-in tab completion to cycle through and select the agent to interact with.

.. code-block:: text

    Merlin[agent][c22c435f-f7c4-445b-bcd4-0d4e020645af]» interact d07edfda-e119-4be2-a20f-918ab701fa3c
    Merlin[agent][d07edfda-e119-4be2-a20f-918ab701fa3c]»

list
----

The ``list`` command returns a list of all created listeners to include some configuration information and status.

.. code-block:: html

    Merlin[listeners]» list

    +---------+-----------+------+----------+---------+------------------+
    |  NAME   | INTERFACE | PORT | PROTOCOL | STATUS  |   DESCRIPTION    |
    +---------+-----------+------+----------+---------+------------------+
    | Default | 127.0.0.1 | 443  |  HTTPS   | Running | Default listener |
    |  HTTP3  | 127.0.0.1 | 443  |  HTTP3   | Running | Default listener |
    |   H2C   | 127.0.0.1 |  80  |   H2C    | Running | Default listener |
    +---------+-----------+------+----------+---------+------------------+

main
----

The ``main`` command returns to the :doc:`main`.

.. code-block:: html

    Merlin[listeners]» main
    Merlin»

.. _listener sessions:

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
* STATUS - The Agent's communication status of either active, delayed, or dead
* LAST CHECKIN - The amount of time that has passed since the agent last checked in
* NOTE - A free-form text area for operators to record notes about a specific agent; tracked server-side only

.. code-block:: text

    Merlin» sessions

                   AGENT GUID              |    TRANSPORT    |   PLATFORM    |      HOST       |        USER         |                 PROCESS                  | STATUS | LAST CHECKIN |      NOTE
    +--------------------------------------+-----------------+---------------+-----------------+---------------------+------------------------------------------+--------+--------------+-----------------+
      d07edfda-e119-4be2-a20f-918ab701fa3c | HTTP/2 over TLS | linux/amd64   | ubuntu          | rastley             | main(200769)                             | Active | 0:00:08 ago  | Demo Agent Here


start
-----

The ``start`` command is used to start a previously created and stopped Listener by its name.

**NOTE:** Cycle through the available listeners using the tab key after the start command.

.. code-block:: html

    Merlin[listeners]» start Default
    Merlin[listeners]»
    [+] Restarted Default HTTPS listener on 127.0.0.1:443

    [!] Insecure publicly distributed Merlin x.509 testing certificate in use for https server on 127.0.0.1:443
    Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates
    Merlin[listeners]»

stop
----

The ``stop`` command is used to stop a previously created Listener by its name.

**NOTE:** Cycle through the available listeners using the tab key after the stop command.

.. code-block:: html

    Merlin[listeners]» stop Default
    Merlin[listeners]»
    [+] Default listener was stopped
    Merlin[listeners]»

use
---

The `use` command is leveraged to create a new listener. The ``use`` command expects the listener type, by protocol, to follow. Press enter to select a template for the listener type. View the ?? section for additional information on creating a listener.

**NOTE:** Cycle through the available listener types using the tab key after the use command.

.. code-block:: html

    Merlin[listeners]» use http3
    Merlin[listeners][http3]»

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


Instantiated
============

This menu is accessed by issuing the the ``interact`` command followed by the name of previously created (instantiated) Listener. The ``help`` command is used to view available commands for the instantiated Listener menu. Tab completion can be used at any time to provide the user a list of commands that can be selected.

.. code-block:: text

    Merlin[listeners]» configure Default
    Merlin[listeners][Default]» help

      COMMAND |          DESCRIPTION           |        OPTIONS
    +---------+--------------------------------+------------------------+
      back    | Return to the listeners menu   |
      delete  | Delete this listener           | delete <listener_name>
      info    | Display all configurable       |
              | information the current        |
              | listener                       |
      interact| Interact with an agent         | interact <agent_id>
      main    | Return to the main menu        |
      restart | Restart this listener          |
      sessions| List all agents session        |
              | information. Alias for MSF     |
              | users                          |
      set     | Set a configurable option      | set <option_name>
      show    | Display all configurable       |
              | information about a listener   |
      start   | Start this listener            |
      status  | Get the server's current       |
              | status                         |
      stop    | Stop the listener              |
      *       | Anything else will be execute  |
              | on the host operating system   |
    Listener Help Menu

back
----

The ``back`` command is used to move one level back. In this case the command will return the user to the root Listener menu.

.. code-block:: html

    Merlin[listeners][Default]» back
    Merlin[listeners]»

delete
------

The ``delete`` command is used to delete the Listener you are currently interacting with, indicated in the square brackets in the Merlin prompt. The user will be prompted for confirmation to prevent accidentally deleting a listener.

.. code-block:: html

    Merlin[listeners][Default]» delete

    Are you sure you want to delete the Default listener? [yes/NO]:
    yes
    Merlin[listeners]»

info
----

The ``info`` command is used to display information about the Listener you are currently interacting with, indicated in the square brackets in the Merlin prompt.

.. code-block:: html

    Merlin[listeners][Default]» info
    +-------------+--------------------------------------+
    |    NAME     |                VALUE                 |
    +-------------+--------------------------------------+
    | Name        | Default                              |
    +-------------+--------------------------------------+
    | ID          | 2e3025e8-6e8e-4fe1-b69c-5d248e34068c |
    +-------------+--------------------------------------+
    | Interface   | 127.0.0.1                            |
    +-------------+--------------------------------------+
    | Port        | 443                                  |
    +-------------+--------------------------------------+
    | Protocol    | HTTPS                                |
    +-------------+--------------------------------------+
    | PSK         | merlin                               |
    +-------------+--------------------------------------+
    | URLS        | /                                    |
    +-------------+--------------------------------------+
    | X509Cert    |                                      |
    +-------------+--------------------------------------+
    | X509Key     |                                      |
    +-------------+--------------------------------------+
    | Description | Default listener                     |
    +-------------+--------------------------------------+
    | Status      | Running                              |
    +-------------+--------------------------------------+
    Merlin[listeners][Default]»

interact
--------

See the :ref:`listener interact` section

main
----

The ``main`` command returns to the Main menu

.. code-block:: html

    Merlin[listeners][Default]» main
    Merlin»

restart
-------

The ``restart`` command stops the current listener and then immediately starts it. This is useful to apply configuration changes made with the ``set`` command.

.. code-block:: html

    Merlin[listeners][Default]» restart

        [-] Certificate was not found at:
        Creating in-memory x.509 certificate used for this session only
        Merlin[listeners][Default]»
        [+] Default listener was successfully restarted
        Merlin[listeners][Default]»

sessions
--------

See the :ref:`listener sessions` section

set
---

The ``set`` command is used to set the value of a configurable option for the Listener you are currently interacting with. Use the ``show`` command to see a list of configurable options.

**NOTE:** Cycle through the available configurable options for the current Listener using the tab key after the ``set`` command.

.. code-block:: html

    Merlin[listeners][Default]» set Name AcmeHTTPS
    Merlin[listeners][Default]»
    [+] set Name to: AcmeHTTPS
    Merlin[listeners][Default]» set Description Main listener for Acme hacks
    Merlin[listeners][Default]»
    [+] set Description to: Main listener for Acme hacks
    Merlin[listeners][Default]»
    Merlin[listeners][Default]» info
    +-------------+--------------------------------------+
    |    NAME     |                VALUE                 |
    +-------------+--------------------------------------+
    | Port        | 443                                  |
    +-------------+--------------------------------------+
    | URLS        | /                                    |
    +-------------+--------------------------------------+
    | X509Key     |                                      |
    +-------------+--------------------------------------+
    | Description | Main listener for Acme hacks         |
    +-------------+--------------------------------------+
    | Name        | AcmeHTTPS                            |
    +-------------+--------------------------------------+
    | ID          | 2e3025e8-6e8e-4fe1-b69c-5d248e34068c |
    +-------------+--------------------------------------+
    | Interface   | 127.0.0.1                            |
    +-------------+--------------------------------------+
    | Protocol    | HTTPS                                |
    +-------------+--------------------------------------+
    | PSK         | merlin                               |
    +-------------+--------------------------------------+
    | X509Cert    |                                      |
    +-------------+--------------------------------------+
    | Status      | Running                              |
    +-------------+--------------------------------------+
    Merlin[listeners][Default]»

show
----

The ``show`` command is used to show a table of all configurable options.

.. code-block:: html

    Merlin[listeners][Default]» show
    +-------------+--------------------------------------+
    |    NAME     |                VALUE                 |
    +-------------+--------------------------------------+
    | PSK         | merlin                               |
    +-------------+--------------------------------------+
    | Name        | AcmeHTTPS                            |
    +-------------+--------------------------------------+
    | X509Cert    |                                      |
    +-------------+--------------------------------------+
    | X509Key     |                                      |
    +-------------+--------------------------------------+
    | Description | Main listener for Acme hacks         |
    +-------------+--------------------------------------+
    | ID          | 2e3025e8-6e8e-4fe1-b69c-5d248e34068c |
    +-------------+--------------------------------------+
    | Interface   | 127.0.0.1                            |
    +-------------+--------------------------------------+
    | Port        | 443                                  |
    +-------------+--------------------------------------+
    | Protocol    | HTTPS                                |
    +-------------+--------------------------------------+
    | URLS        | /                                    |
    +-------------+--------------------------------------+
    | Status      | Running                              |
    +-------------+--------------------------------------+
    Merlin[listeners][Default]»

start
-----

The ``start`` command is used to start the current Listener you are interacting with, indicated in the square brackets in the Merlin prompt.

.. code-block:: html

    Merlin[listeners][Default]» start

    [-] Certificate was not found at:
    Creating in-memory x.509 certificate used for this session only
    Merlin[listeners][Default]»
    [+] Restarted Default HTTPS listener on 127.0.0.1:443
    Merlin[listeners][Default]»

status
------

The ``status`` command is used to quickly determine if the Listener's server you are currently interacting with is running or stopped.

.. code-block:: html

    Merlin[listeners][Default]» status
    Merlin[listeners][Default]»
    Running
    Merlin[listeners][Default]»

stop
----

The ``stop`` command is used to stop the current Listener you are interacting with, indicated in the square brackets in the Merlin prompt.

.. code-block:: html

    Merlin[listeners][Default]» stop
    Merlin[listeners][Default]»
    [+] Default listener was stopped
    Merlin[listeners][Default]»

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

Template
========

The Listener Template menu is accessed by issuing the ``use`` command followed by a valid listener type from the Listener Main menu. The ``help`` command is used to view available commands for the Listener menu. Tab completion can be used at any time to provide the user a list of commands that can be selected.

.. code-block:: text

    Merlin[listeners]» use https
    Merlin[listeners][https]» help

          COMMAND |          DESCRIPTION           |      OPTIONS
        +---------+--------------------------------+-------------------+
          back    | Return to the listeners menu   |
          execute | Create and start the listener  |
                  | (alias)                        |
          info    | Display all configurable       |
                  | information about a listener   |
          interact| Interact with an agent         | interact <agent_id>
          main    | Return to the main menu        |
          run     | Create and start the listener  |
                  | (alias)                        |
          sessions| List all agents session        |
                  | information. Alias for MSF     |
                  | users                          |
          set     | Set a configurable option      | set <option_name>
          show    | Display all configurable       |
                  | information about a listener   |
          start   | Create and start the listener  |
          *       | Anything else will be execute  |
                  | on the host operating system   |
        Listener Setup Help Menu

back
----

The ``back`` command is used to move one level back. In this case the command will return the user to the root Listener menu.

.. code-block:: html

    Merlin[listeners][https]» back
    Merlin[listeners]»

execute
-------

The ``execute`` command is used to create and start the Listener from the configured template options. This is an alias for the ``start`` command.

.. code-block:: html

    Merlin[listeners]» use https
    Merlin[listeners][https]» execute

    [!] Insecure publicly distributed Merlin x.509 testing certificate in use for https server on 127.0.0.1:443
    Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates

    [+] Default listener was created with an ID of: f6826564-000a-4edf-94b2-b79ee7d892a5

    [+] Started HTTPS listener on 127.0.0.1:443
    Merlin[listeners][Default]»

info
----

The ``info`` command is used to display the Listener template configurable options and their current value.

.. code-block:: html

    Merlin[listeners]» use https
    Merlin[listeners][https]» info
    +-------------+------------------+
    |    NAME     |      VALUE       |
    +-------------+------------------+
    | PSK         | merlin           |
    +-------------+------------------+
    | Interface   | 127.0.0.1        |
    +-------------+------------------+
    | Port        | 443              |
    +-------------+------------------+
    | URLS        | /                |
    +-------------+------------------+
    | X509Cert    |                  |
    +-------------+------------------+
    | X509Key     |                  |
    +-------------+------------------+
    | Name        | Default          |
    +-------------+------------------+
    | Description | Default listener |
    +-------------+------------------+
    | Protocol    | https            |
    +-------------+------------------+
    Merlin[listeners][https]»

interact
--------

See the :ref:`listener interact` section

main
----

The ``main`` command returns to the Main menu

.. code-block:: html

    Merlin[listeners][https]» main
    Merlin»

run
---

The ``run`` command is used to create and start the Listener from the configured template options. This is an alias for the ``start`` command.

.. code-block:: html

    Merlin[listeners]» use https
    Merlin[listeners][https]» run

    [!] Insecure publicly distributed Merlin x.509 testing certificate in use for https server on 127.0.0.1:443
    Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates

    [+] Default listener was created with an ID of: 632db67c-7045-462f-bf09-aea90272aed5
    Merlin[listeners][Default]»
    [+] Started HTTPS listener on 127.0.0.1:443
    Merlin[listeners][Default]»

sessions
--------

See the :ref:`listener sessions` section

set
---

The ``set`` command is used to set the value of a configurable option for the Listener you are currently interacting with. Use the ``show`` command to see a list of configurable options.

**NOTE:** Cycle through the available configurable options for the current Listener using the tab key after the ``set`` command.

.. code-block:: html

    Merlin[listeners]» use https
    Merlin[listeners][https]» set Name Merlin Demo Listener
    [+] set Name to: Merlin Demo Listener
    Merlin[listeners][https]»

show
----

The ``show`` command is used to display the Listener template configurable options and their current value.

.. code-block:: html

    Merlin[listeners][https]» show
    +-------------+-----------------------------------------------------------------+
    |    NAME     |                              VALUE                              |
    +-------------+-----------------------------------------------------------------+
    | URLS        | /                                                               |
    +-------------+-----------------------------------------------------------------+
    | X509Cert    | /home/joe/go/src/github.com/Ne0nd0g/merlin/data/x509/server.crt |
    +-------------+-----------------------------------------------------------------+
    | Protocol    | https                                                           |
    +-------------+-----------------------------------------------------------------+
    | Interface   | 127.0.0.1                                                       |
    +-------------+-----------------------------------------------------------------+
    | Port        | 443                                                             |
    +-------------+-----------------------------------------------------------------+
    | PSK         | merlin                                                          |
    +-------------+-----------------------------------------------------------------+
    | X509Key     | /home/joe/go/src/github.com/Ne0nd0g/merlin/data/x509/server.key |
    +-------------+-----------------------------------------------------------------+
    | Name        | Merlin Demo Listener                                            |
    +-------------+-----------------------------------------------------------------+
    | Description | Default listener                                                |
    +-------------+-----------------------------------------------------------------+
    Merlin[listeners][https]»

start
-----

The ``start`` command is used to create and start the Listener from the configured template options.

.. code-block:: html

    Merlin[listeners]» use https
    Merlin[listeners][https]» start

    [+] Default listener was created with an ID of: 20b337ba-01d4-44eb-9ebd-cdebf156967e

    [+] Started HTTPS listener on 127.0.0.1:443

    [!] Insecure publicly distributed Merlin x.509 testing certificate in use for https server on 127.0.0.1:443
    Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates
    Merlin[listeners][Default]»

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
