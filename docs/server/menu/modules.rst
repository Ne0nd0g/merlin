############
Modules Menu
############

The module menu context is used to interact with, and configure, a module. The Merlin prompt will include the word module along with the identifier for the selected module. Type ``help`` to see a list of available commands for the agent menu context.

.. code-block:: html

    Merlin» use module windows/x64/powershell/powersploit/Invoke-Mimikatz
    Merlin[module][Invoke-Mimikatz]» help

      COMMAND |          DESCRIPTION           |           OPTIONS
    +---------+--------------------------------+------------------------------+
      back    | Return to the main menu        |
      info    | Show information about a       |
              | module                         |
      main    | Return to the main menu        |
      reload  | Reloads the module to a fresh  |
              | clean state                    |
      run     | Run or execute the module      |
      set     | Set the value for one of the   | <option name> <option value>
              | module's options               |
      show    | Show information about a       | info, options
              | module or its options          |

.. _back:

back
----

The ``back`` command is used to leave the Module menu and return back to the :doc:`main`.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» back
    Merlin»

info
----

The ``info`` command command is used to print all of the information about a module to the screen. This information includes items such as module's name, authors, credits, description, notes, and configurable options. This is an alias for the ``show info`` command.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» show info
    Module:
            Invoke-Mimikatz
    Platform:
            windows\x64\PowerShell
    Authors:
            Russel Van Tuyl (@Ne0nd0g)
    Credits:
            Joe Bialek (@JosephBialek)
            Benjamin Delpy (@gentilkiwi)
    Description:
            This script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory. This allows you to do things such as dump credentials without ever writing the mimikatz binary to disk. The script has a ComputerName parameter which allows it to be executed against multiple computers. This script should be able to dump credentials from any version of Windows through Windows 8.1 that has PowerShell v2 or higher installed.

    Agent: 00000000-0000-0000-0000-000000000000

    Module options(Invoke-Mimikatz)

          NAME     |                VALUE                 | REQUIRED |          DESCRIPTION
    +--------------+--------------------------------------+----------+--------------------------------+
      Agent        | 00000000-0000-0000-0000-000000000000 | true     | Agent on which to run module
                   |                                      |          | Invoke-Mimikatz
      DumpCreds    | true                                 | false    | [Switch]Use mimikatz to dump
                   |                                      |          | credentials out of LSASS.
      DumpCerts    |                                      | false    | [Switch]Use mimikatz to export
                   |                                      |          | all private certificates
                   |                                      |          | (even if they are marked
                   |                                      |          | non-exportable).
      Command      |                                      | false    | Supply mimikatz a custom
                   |                                      |          | command line. This works
                   |                                      |          | exactly the same as running
                   |                                      |          | the mimikatz executable
                   |                                      |          | like this: mimikatz
                   |                                      |          | "privilege::debug exit" as an
                   |                                      |          | example.
      ComputerName |                                      | false    | Optional, an array of
                   |                                      |          | computernames to run the
                   |                                      |          | script on.

    Notes: This is part of the PowerSploit project https://github.com/PowerShellMafia/PowerSploit


main
----

The ``main`` command is used to leave the Agent menu and return back to the :doc:`main`. It is an alias for the back_ command.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» main
    Merlin»

reload
------

The ``reload`` command is used to clear out all of a module's configurable options and return its settings to the default state.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» reload
    Merlin[module][Invoke-Mimikatz]»

run
---

The ``run`` command is used to execute the module on the agent configured for the module's [agent](#set-agent) value.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» run
    Merlin[module][Invoke-Mimikatz]» [-]Created job iReycchrck for agent ebf1b1d2-44d5-4f85-86f5-cae112600870
    [+]Results for job iReycchrck
    [+]
      .#####.   mimikatz 2.1 (x64) built on Nov 10 2016 15:31:14
     .## ^ ##.  "A La Vie, A L'Amour"
     ## / \ ##  /* * *
     ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
      '#####'                                     with 20 modules * * */
    <snip>
    Merlin[module][Invoke-Mimikatz]»

set
---

The ``set`` command is used to set the value for one of the module's configurable options. This command is used by specifying the name of the option that should be set followed by a value. Tab completion is enabled and provides a list of all configurable options.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» set DumpCerts true
    [+]DumpCerts set to true
    Merlin[module][Invoke-Mimikatz]»

.. _set-agent:

set Agent
^^^^^^^^^

The `Agent` *option* for every module must be set in order for it have a target to execute on. By default, the module is configured with a blank value of ``00000000-0000-0000-0000-000000000000``. To set an agent, provide the agent's ID (tab completion enabled).

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» set agent c1090dbc-f2f7-4d90-a241-86e0c0217786
    [+]agent set to c1090dbc-f2f7-4d90-a241-86e0c0217786
    Merlin[module][Invoke-Mimikatz]»


The special value ``all`` can be provided and instructs Merlin to execute the module on all agents. When this value is provided, the module's agent option is set to all F's like: ``ffffffff-ffff-ffff-ffff-ffffffffffff``

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» set agent all
    [+]agent set to ffffffff-ffff-ffff-ffff-ffffffffffff
    Merlin[module][Invoke-Mimikatz]»

show
----

The ``show`` command is used to retrieve information about the module itself. This command uses additional options to specify what information should be retrieved.

Options:

* info_
* options_

.. _info:

info
^^^^

The ``info`` sub-command for the ``show`` command is used to print all of the information about a module to the screen. This information includes items such as module's name, authors, credits, description, notes, and configurable options.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» show info
    Module:
            Invoke-Mimikatz
    Platform:
            windows\x64\PowerShell
    Authors:
            Russel Van Tuyl (@Ne0nd0g)
    Credits:
            Joe Bialek (@JosephBialek)
            Benjamin Delpy (@gentilkiwi)
    Description:
            This script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory. This allows you to do things such as dump credentials without ever writing the mimikatz binary to disk. The script has a ComputerName parameter which allows it to be executed against multiple computers. This script should be able to dump credentials from any version of Windows through Windows 8.1 that has PowerShell v2 or higher installed.

    Agent: 00000000-0000-0000-0000-000000000000

    Module options(Invoke-Mimikatz)

          NAME     |                VALUE                 | REQUIRED |          DESCRIPTION
    +--------------+--------------------------------------+----------+--------------------------------+
      Agent        | 00000000-0000-0000-0000-000000000000 | true     | Agent on which to run module
                   |                                      |          | Invoke-Mimikatz
      DumpCreds    | true                                 | false    | [Switch]Use mimikatz to dump
                   |                                      |          | credentials out of LSASS.
      DumpCerts    |                                      | false    | [Switch]Use mimikatz to export
                   |                                      |          | all private certificates
                   |                                      |          | (even if they are marked
                   |                                      |          | non-exportable).
      Command      |                                      | false    | Supply mimikatz a custom
                   |                                      |          | command line. This works
                   |                                      |          | exactly the same as running
                   |                                      |          | the mimikatz executable
                   |                                      |          | like this: mimikatz
                   |                                      |          | "privilege::debug exit" as an
                   |                                      |          | example.
      ComputerName |                                      | false    | Optional, an array of
                   |                                      |          | computernames to run the
                   |                                      |          | script on.

    Notes: This is part of the PowerSploit project https://github.com/PowerShellMafia/PowerSploit

options
^^^^^^^

The ``options`` sub-command for the `show` command is used to print *only* the configurable options along with their current value.

.. code-block:: html

    Merlin[module][Invoke-Mimikatz]» show options

    Agent: 00000000-0000-0000-0000-000000000000

    Module options(Invoke-Mimikatz)

          NAME     |                VALUE                 | REQUIRED |          DESCRIPTION
    +--------------+--------------------------------------+----------+--------------------------------+
      Agent        | 00000000-0000-0000-0000-000000000000 | true     | Agent on which to run module
                   |                                      |          | Invoke-Mimikatz
      DumpCreds    | true                                 | false    | [Switch]Use mimikatz to dump
                   |                                      |          | credentials out of LSASS.
      DumpCerts    |                                      | false    | [Switch]Use mimikatz to export
                   |                                      |          | all private certificates
                   |                                      |          | (even if they are marked
                   |                                      |          | non-exportable).
      Command      |                                      | false    | Supply mimikatz a custom
                   |                                      |          | command line. This works
                   |                                      |          | exactly the same as running
                   |                                      |          | the mimikatz executable
                   |                                      |          | like this: mimikatz
                   |                                      |          | "privilege::debug exit" as an
                   |                                      |          | example.
      ComputerName |                                      | false    | Optional, an array of
                   |                                      |          | computernames to run the
                   |                                      |          | script on.
