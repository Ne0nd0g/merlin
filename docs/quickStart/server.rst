Merlin Server
=============

The quickest and recommended way is to download Merlin Server from the `releases <https://github.com/Ne0nd0g/merlin/releases>`_ page for your host operating system (i.e Windows, macOS, or Linux).

Ubuntu Server 18.04
-------------------

The following single line of code can be used to download, extract, and run Merlin Server on an Ubuntu Server:

.. code-block:: bash

 sudo bash;apt update;apt install p7zip-full -y;cd /opt;wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z;7z x -pmerlin -omerlin merlinServer-Linux-x64.7z;cd merlin;./merlinServer-Linux-x64


If you're using 7zip from the command line, but sure to use the ``x`` flag so that the files are extracted into their respective directories.

**The Merlin Server file download includes the compiled agents for all 3 major platforms in the** ``data/bin/`` **directory**

Visit the :doc:`agent` quick start to launch an agent.