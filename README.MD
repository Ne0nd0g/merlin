[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/yadppqp12h445akx/branch/master?svg=true)](https://ci.appveyor.com/project/Ne0nd0g/merlin/branch/master)
[![GoReportCard](https://goreportcard.com/badge/github.com/Ne0nd0g/merlin)](https://goreportcard.com/report/github.com/Ne0nd0g/merlin)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/Ne0nd0g/merlin.svg)](https://github.com/Ne0nd0g/merlin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Ne0nd0g/merlin/total.svg)](https://github.com/Ne0nd0g/merlin/releases)
[![Twitter Follow](https://img.shields.io/twitter/follow/merlin_c2.svg?style=social&label=Follow)](https://twitter.com/merlin_c2)

# Merlin

<p align="center">
  <img alt="Merlin Logo" src="docs/images/merlin.png" height="30%" width="30%">
</p>

Merlin is a cross-platform post-exploitation Command & Control server and agent written in Go.

Highlighted features:

- Supported C2 Protocols: http/1.1 clear-text, http/1.1 over TLS, HTTP/2, HTTP/2 clear-text (h2c), http/3 (http/2 over QUIC)
- Server and Agent: Windows, Linux, macOS (Darwin), MIPS, ARM or anything Go can [natively build](https://golang.org/doc/install/source#environment)
  - [Windows DLL Agent](https://github.com/Ne0nd0g/merlin-agent-dll)
- Domain Fronting
- Execute .NET assemblies in-process with `invoke-assembly` or in a sacrificial process with `execute-assembly`
- Execute arbitrary Windows executables (PE) in a sacrificial process with `execute-pe` 
- Various shellcode execution techniques: CreateThread, CreateRemoteThread,  RtlCreateUserThread, QueueUserAPC
- [OPAQUE](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00) Asymmetric Password Authenticated Key Exchange (PAKE)
- Encrypted JWT for authentication
- Agent traffic is an encrypted JWE using PBES2 (RFC 2898) with HMAC SHA-512 as the PRF and AES Key Wrap (RFC 3394) 
  using 256-bit keys for the encryption scheme. ([PBES2_HS512_A256KW](https://tools.ietf.org/html/rfc7518#section-4.8))
- Integrated [Donut](https://github.com/Binject/go-donut), [sRDI](https://github.com/monoxgas/sRDI), 
  and [SharpGen](https://github.com/cobbr/SharpGen) support
- C2 traffic message [padding](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#padding) to combat 
  beaconing detections based on a fixed message size
- Dynamically change the Agent's [JA3](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#ja3) hash 
- [Mythic](#mythic) support
- [Documentation & Wiki](https://merlin-c2.readthedocs.io/en/latest/)

An introductory blog post can be found here: <https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a>

## Quick Start

1. Download the latest compiled version of Merlin Server from the [releases](https://github.com/Ne0nd0g/merlin/releases) section
   > The Server package contains a compiled Agent for all the major operating systems in the `data/bin` directory
2. Extract the files with 7zip using the `x` function **The password is: `merlin`**
3. Start Merlin
4. Configure a [listener]()   
5. Deploy an agent. See [Agent Execution Quick Start Guide](https://merlin-c2.readthedocs.io/en/latest/quickStart/agent.html) for examples
6. Pwn, Pivot, Profit

   ```
   mkdir /opt/merlin;cd /opt/merlin
   wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
   7z x merlinServer-Linux-x64.7z
   sudo ./merlinServer-Linux-x64
   ```

## Agents

The [Merlin Agent](https://github.com/Ne0nd0g/merlin-agent) is kept in its own repository so that it can easily be 
retrieved and compiled:

```text
go get github.com/Ne0nd0g/merlin-agent
```

The [Windows DLL Agent](https://github.com/Ne0nd0g/merlin-agent-dll) is also kept in a separate repository.
See the [DLL Agent](https://merlin-c2.readthedocs.io/en/latest/agent/dll.html) documentation for building instructions.

## Mythic

The Merlin server is a self-contained command line program that requires no installation. You just simply download it 
and run it.
The command-line interface only works great if it will be used by a single operator at a time. 
The Merlin agent can be controlled through [Mythic](https://github.com/its-a-feature/Mythic), which features a web-based
user interface that enables multiplayer support, and a slew of other features inherent to the project.

Visit the [Merlin](https://github.com/MythicAgents/merlin) repository in the MythicAgents organizaiton to get started.

## Misc.

* The latest development build of Merlin can be downloaded from [AppVeyor](https://ci.appveyor.com/project/Ne0nd0g/merlin-i9c58/build/artifacts)
* To compile Merlin from source, view the [Custom Build](https://merlin-c2.readthedocs.io/en/latest/agent/custom.html) page
* For a full list of available commands:
   * [Main Menu](https://merlin-c2.readthedocs.io/en/latest/server/menu/main.html)
   * [Listener Menu](https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html)
   * [Agent Menu](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html)
   * [Module Menu](https://merlin-c2.readthedocs.io/en/latest/server/menu/modules.html)
* View the [Frequently Asked Questions](https://merlin-c2.readthedocs.io/en/latest/quickStart/faq.html) page
* View the [Blog Posts](https://merlin-c2.readthedocs.io/en/latest/misc/blogs.html) page for additional information

## Slack

Join the `#merlin` channel in the [BloodHoundGang](https://bloodhoundgang.herokuapp.com/) Slack to ask questions, 
troubleshoot, or provide feedback.

## JetBrains

Thanks to [JetBrains](https://www.jetbrains.com/?from=merlin) for kindly sponsoring Merlin by providing a Goland IDE 
Open Source license

<p align="center">
  <img alt="JetBrains Logo" src="docs/images/jetbrains-variant-4.png" height="40%" width="40%">
  <img alt="GoLand Logo" src="docs/images/icon-goland.png" height="20%" width="20%">
</p>
 