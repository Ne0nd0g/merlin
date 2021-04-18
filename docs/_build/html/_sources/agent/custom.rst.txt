############
Custom Build
############

This section details how to build custom build a Merlin Agent using the Make file.

**NOTE:** Merlin is distributed with pre-compiled agent binaries for all major platforms in the ``data/bin`` directory.

Basic
-----

The provided Make file can be used to build a new agent from **source**. It is recommended that you first use
``go get github.com/Ne0nd0g/merlin-agent`` to pull a copy of the Merlin source code to the host. Move into the Merlin root
directory where the Make file is located.

* Windows agent: ``make windows``
* Linux agent: ``make linux``
* macOS agent: ``make darwin``
* MIPS agent: ``make mips``
* ARM agent: ``make arm``

Advanced
--------

Use the provided Make file to build a Merlin Agent with hard coded values. This removes the need for an operator to use
commandline arguments and allows the Agent to simply be executed. The table below shows configurable compile options

.. csv-table:: Build Options
   :header: "Option", "Description", "Notes"
   :widths: auto

    HOST, HTTP Host header, same as ``-host`` commandline flag
    JA3, JA3 signature string (not the MD5 hash). Overrides -proto flag, same as ``-ja3`` commandline flag
    KILLDATE, "The date, as a Unix EPOCH timestamp, that the agent will quit running", same as ``-killdate`` commandline flag
    MAXRETRY, The maximum amount of failed checkins before the agent will quit running, same as ``-maxretry`` commandline flag
    PADDING, The maximum amount of data that will be randomly selected and appended to every message, same as ``-padding`` commandline flag
    PROTO, "Protocol for the agent to connect with [https (HTTP/1.1), http (HTTP/1.1 Clear-Text), h2 (HTTP/2), h2c (HTTP/2 Clear-Text), http3 (QUIC or HTTP/3.0)] (default 'h2')", same as ``-proto`` commandline flag
    PROXY, Hardcoded proxy to use for http/1.1 traffic only that will override host configuration, same as ``-proxy`` commandline flag
    PSK, Pre-Shared Key used to encrypt initial communications (default "merlin"), same as ``-psk`` commandline flag
    SKEW, "Amount of skew, or variance, between agent checkins", same as ``-skew`` commandline flag
    SLEEP, "The amount of time the Agent will sleep between checkins Must use golang time notation (e.g., ``10s`` for ten seconds)", same as ``-sleep`` command line flag
    URL, Full URL for agent to connect to (default "https://127.0.0.1:443"), same as the ``-url`` commandline flag
    USERAGENT, The HTTP User-Agent header string that Agent will use while sending traffic, same sas the ``-useragent`` commandline flag

An example of creating a new Linux HTTP agent that is using domain fronting through ``https://merlin.com/c2endpoint.php`` using a PSK of ``SecurePassword1``:

``make linux URL=https://merlin.com:443/c2endpoint.php HOST=myendpoint.azureedge.net PROTO=https PSK=SecurePassword1``

Windows Agent
-------------

The Windows Merlin Agent executable is compiled as a GUI application instead of console application. The Merlin Agent
does not have a GUI component. The reason this is used is so that the Merlin Agent window disappears after it is executed.
This behavior is intentional so that the user will not see the application window. This is done with the LDFLAGS when
building the agent using the ``-H=windowsgui`` option as shown `here <https://golang.org/cmd/link/>`_

This causes problems when a user **WANTS** to see the Merlin Agent verbose or debug output. To view Merlin verbose/debug
output, use the Makefile ``windows-debug`` target (e.g., ``make windows-debug``)

Cross-Compiling
---------------

The Merlin agent and server can be cross-compiled to any operating system or architecture.
A list of golang supported operating systems and architectures can be found here: https://golang.org/doc/install/source#environment

.. csv-table:: Supported Platforms
   :header: "$GOOS", "$GOARCH"
   :widths: auto

    android,arm
    darwin,386
    darwin,amd64
    darwin,arm
    darwin,arm64
    dragonfly,amd64
    freebsd,386
    freebsd,amd64
    freebsd,arm
    linux,386
    linux,amd64
    linux,arm
    linux,arm64
    linux,ppc64
    linux,ppc64le
    linux,mips
    linux,mipsle
    linux,mips64
    linux,mips64le
    netbsd,386
    netbsd,amd64
    netbsd,arm
    openbsd,386
    openbsd,amd64
    openbsd,arm
    plan9,386
    plan9,amd64
    solaris,amd64
    windows,386
    windows,amd64

Mobile
------

The gomobile library can be used to compile for Android and iOS:
 https://godoc.org/golang.org/x/mobile/cmd/gomobile

These instructions can be followed to compile for Android

* Install Android SDK: https://developer.android.com/ndk/guides/index.html
* Install gomobile:
    ``go get golang.org/x/mobile/cmd/gomobile``
* Initialize gomobile:
    ``bin\gomobile init -ndk=C:\Users\[username]\AppData\Local\Android\Sdk\ndk-bundle``
* Build the APK:
    ``bin\gomobile build -target=android merlinagent``