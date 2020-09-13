###
FAQ
###

Frequently Asked Questions


When I double click the pre-compiled Windows agent binary, nothing happens.
---------------------------------------------------------------------------

The pre-compiled Merlin Agent for Windows is compiled with an option that prevents the program from showing. Double clicking the ``merlinAgent-Windows-x64.exe`` file will launch the agent and it will connect to the hard coded URL (default is ``https://127.0.0.1:443/``). The agent will eventually die once it fails to contact the server. Options include recompiling merlinAgent with the hard coded URL of your server or running it from the command line using the ``-url`` flag to specify your server. View the :doc:`./../agent/custom` page for details on building and compiling the agent from source. Additionally, the agent can be compiled without the ``-H=windowsgui`` so that it doesn't disappear when executed by double clicking the file.

I get errors when trying to compile Merlin.
-------------------------------------------

The biggest contributor I see for getting errors while compiling is forgetting to ensure the `GOPATH` environment variable is set. View the :doc:`./../agent/custom` page for details on ensuring the environment is configured properly.

Input and output redirection pipes don't work
---------------------------------------------

Pipes ``|`` and redirectors ``<`` and ``>`` are functions of a shell. By default, Merlin only executes programs in the host's PATH variable. In order to use pipes and redirection, you must first specify the shell (i.e ``/bin/bash``) so that you can use these.

When running a Merlin agent on a Linux host, use the ``-c`` flag with the shell to effectively change directories and perform some action in that directory. Because Merlin spawns a process for every command, the shell is not persistent or interactive. This request the operator to combine multiple commands together so that they are all in the same context/environment.

Example:

``Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»shell /bin/sh -c "ls -l > /tmp/out.txt"``
