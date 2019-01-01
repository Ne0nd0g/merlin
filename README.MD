[![GoReportCard](https://goreportcard.com/badge/github.com/ne0nd0g/merlin)](https://goreportcard.com/badge/github.com/ne0nd0g/merlin)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/Ne0nd0g/merlin.svg)](https://github.com/Ne0nd0g/merlin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Ne0nd0g/merlin/total.svg)](https://github.com/Ne0nd0g/merlin/releases)
[![Slack](https://img.shields.io/badge/Slack-Sign--Up-blue.svg)](https://communityinviter.com/apps/merlin-go/merlin)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/Ne0nd0g/merlin?branch=dev&svg=true)](https://ci.appveyor.com/project/Ne0nd0g/merlin)

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
1. Download the latest version of Merlin Server from the [releases](https://github.com/Ne0nd0g/merlin/releases) section
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
* To compile Merlin from source, view the [Building or Running from Source](https://github.com/Ne0nd0g/merlin/wiki/Building-or-Running-from-Source) wiki page
* For a full list of available commands view the [Main Menu](https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Main-Menu), [Agent Menu](https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Agent-Menu), and [Module Menu](https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Module-Menu) wiki pages
* View the [FAQ](https://github.com/Ne0nd0g/merlin/wiki/FAQ) wiki page for Frequently Asked Questions
* View the [Blog Posts](https://github.com/Ne0nd0g/merlin/wiki/Blog-Posts) page for additional information

## Merlin Server Command Line Flags
`./merlinServer-Linux-x64 -h`
```
  -debug
        Enable debug output
  -i string
        The IP address of the interface to bind to (default "0.0.0.0")
  -p int
        Merlin Server Port (default 443)
  -v    Enable verbose output
  -x509cert string
        The x509 certificate for the HTTPS listener (default "C:\\Merlin\\data\\x509\\server.crt")
  -x509key string
        The x509 certificate key for the HTTPS listener (default "C:\\Merlin\\data\\x509\\server.key")
```

## Merlin Agent Command Line Flags
`./merlinAgent-Linux-x64 -h`
```
  -debug
        Enable debug output
  -sleep duration
        Time for agent to sleep (default 10s)
  -skew int
        Variable time skew for agent to sleep
  -url string
        Full URL for agent to connect to (default "https://127.0.0.1:443")
  -v    Enable verbose output
```

## TLS Certificates
### **`WARNING: You should generate your own TLS certificates and replace the default certificates that ship with Merlin`**

To facilitate ease of use, a TLS X.509 private and public certificate is distributed with Merlin. This allows a user to start using Merlin right away. However, this key is widely distributed and is considered public knowledge. You should generate your own certificates and replace the default certificates that ship with Merlin. The default location for the certificates is the `data/x509` directory. The `openssl` command can be used from a Linux system to generate a key pair.
