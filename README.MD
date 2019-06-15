[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/Ne0nd0g/merlin?branch=dev&svg=true)](https://ci.appveyor.com/project/Ne0nd0g/merlin)
[![GoReportCard](https://goreportcard.com/badge/github.com/ne0nd0g/merlin)](https://goreportcard.com/badge/github.com/ne0nd0g/merlin)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/Ne0nd0g/merlin.svg)](https://github.com/Ne0nd0g/merlin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Ne0nd0g/merlin/total.svg)](https://github.com/Ne0nd0g/merlin/releases)
[![Twitter Follow](https://img.shields.io/twitter/follow/merlin_c2.svg?style=social&label=Follow)](https://twitter.com/merlin_c2)

# Merlin (BETA)

<p align="center">
  <img src="https://i.imgur.com/4iKuvuj.jpg" height="30%" width="30%">
</p>

Merlin is a cross-platform post-exploitation HTTP/2 Command & Control 
server and agent written in golang.

An introductory blog post can be found here:
https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a


[![asciicast](https://asciinema.org/a/166722.png)](https://asciinema.org/a/166722?speed=2)

## Quick Start
1. Download the latest compiled version of Merlin Server from the [releases](https://github.com/Ne0nd0g/merlin/releases) section
2. Extract the files with 7zip using the `x` function. **The password is: `merlin`**
3. Start Merlin
4. Deploy an agent. See [Agent Execution Quick Start Guide](https://github.com/Ne0nd0g/merlin/wiki/Agent-Execution-Quick-Start-Guide) for examples
5. Pwn, Pivot, Profit

```
mkdir /opt/merlin;cd /opt/merlin
wget https://github.com/Ne0nd0g/merlin/releases/download/v0.1.4/merlinServer-Linux-x64-v0.1.4.7z
7z x merlinServer-Linux-x64-v0.1.4.7z
sudo ./merlinServer-Linux-x64
```

## Misc.
* The latest development build of Merlin can be downloaded from [AppVeyor](https://ci.appveyor.com/project/Ne0nd0g/merlin-i9c58/build/artifacts)
* To compile Merlin from source, view the [Building or Running from Source](https://github.com/Ne0nd0g/merlin/wiki/Building-or-Running-from-Source) wiki page
* For a full list of available commands view the [Main Menu](https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Main-Menu), [Agent Menu](https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Agent-Menu), and [Module Menu](https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Module-Menu) wiki pages
* View the [FAQ](https://github.com/Ne0nd0g/merlin/wiki/FAQ) wiki page for Frequently Asked Questions
* View the [Blog Posts](https://github.com/Ne0nd0g/merlin/wiki/Blog-Posts) page for additional information

## Merlin Server Command Line Flags
`./merlinServer-Linux-x64 -h`
```
Version: 0.8.0.BETA
Build: nonRelease
  -debug
        Enable debug output
  -i string
        The IP address of the interface to bind to (default "127.0.0.1")
  -p int
        Merlin Server Port (default 443)
  -proto string
        Protocol for the agent to connect with [h2, hq] (default "h2")
  -psk string
        Pre-Shared Key used to encrypt initial communications (default "merlin")
  -v    Enable verbose output
  -x509cert string
        The x509 certificate for the HTTPS listener (default "/opt/merlin/data/x509/server.crt")
  -x509key string
        The x509 certificate key for the HTTPS listener (default "/opt/merlin/data/x509/server.key")
```

## Merlin Agent Command Line Flags
`./merlinAgent-Linux-x64 -h`
```
Merlin Agent
  -debug
        Enable debug output
  -proto string
        Protocol for the agent to connect with [h2, hq] (default "h2")
  -psk string
        Pre-Shared Key used to encrypt initial communications (default "merlin")
  -sleep duration
        Time for agent to sleep (default 30s)
  -url string
        Full URL for agent to connect to (default "https://127.0.0.1:443")
  -v    Enable verbose output
  -version
        Print the agent version and exit
```

## Slack

Join the `#merlin` channel in the [BloodHoundGang](https://bloodhoundgang.herokuapp.com/) Slack to chat about Merlin