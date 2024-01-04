[![CodeQL](https://github.com/Ne0nd0g/merlin/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ne0nd0g/merlin/actions/workflows/codeql.yml)
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

- [merlin-cli](https://github.com/Ne0nd0g/merlin-cli) command line interface over gRPC to connect to the Merlin Server facilitating multi-user support
- Supported Agent C2 Protocols: http/1.1 clear-text, http/1.1 over TLS, HTTP/2, HTTP/2 clear-text (h2c), http/3 (http/2 over QUIC)
- Peer-to-peer (P2P) communication between Agents with bind or reverse for SMB, TCP, and UDP
- Configurable agent data encoding and encryption transforms: AES, Base64, gob, hex, JWE, RC4, and XOR
    - JWE transform use [PBES2_HS512_A256KW](https://tools.ietf.org/html/rfc7518#section-4.8) PBES2 (RFC 2898) with HMAC
  SHA-512 as the PRF and AES Key Wrap (RFC 3394) using 256-bit keys for the encryption scheme 
- Configurable agent authenticators:
  - None: No authentication 
  - [OPAQUE](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00): Asymmetric Password Authenticated Key Exchange (PAKE)
- Encrypted JWT for message authentication
- Configurable Agent message data [padding](https://merlin-c2.readthedocs.io/en/latest/agent/cli.html#padding) 
  to combat beaconing detections based on a fixed message size
- Execute .NET assemblies in-process with `invoke-assembly` or in a sacrificial process with `execute-assembly`
- Execute arbitrary Windows executables (PE) in a sacrificial process with `execute-pe` 
- Various shellcode execution techniques: CreateThread, CreateRemoteThread, RtlCreateUserThread, QueueUserAPC
- Integrated [Donut](https://github.com/Binject/go-donut), [sRDI](https://github.com/monoxgas/sRDI), 
  and [SharpGen](https://github.com/cobbr/SharpGen) support
- Dynamically change the Agent's [JA3](https://merlin-c2.readthedocs.io/en/latest/agent/cli.html#ja3) hash 
- [Mythic](#mythic) support
- [Documentation & Wiki](https://merlin-c2.readthedocs.io/en/latest/)

An introductory blog post can be found here: <https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a>

Supporting Repositories:
- [Merlin Agent](https://github.com/Ne0nd0g/merlin-agent) - Agent source code
- [Merlin Agent DLL](https://github.com/Ne0nd0g/merlin-agent-dll) - Agent DLL source code
- [Merlin CLI](https://github.com/Ne0nd0g/merlin-cli) - Command line interface for Merlin
- [Merlin Documentation](https://github.com/Ne0nd0g/merlin-documentation) - Documentation source code
- [Merlin on Mythic](https://github.com/MythicAgents/merlin) - Merlin agent for Mythic Framework
- [Merlin Docker](https://github.com/Ne0nd0g/merlin-docker) - Base Docker image for for Merlin images
- [Merlin Message](https://github.com/Ne0nd0g/merlin-message) - A Go library for Merlin messages exchanged between a Merlin Server and Agent

## Quick Start

1. Download the latest version of Merlin Server from the [releases](https://github.com/Ne0nd0g/merlin/releases) section
   > The Server package contains compiled versions of the CLI and Agent for all the major operating systems in the `data/bin` directory
2. Extract the files with 7zip using the `x` function **The password is: `merlin`**
3. Start Merlin
4. Start the CLI
5. Configure a [listener](https://merlin-c2.readthedocs.io/en/latest/cli/menu/listeners.html)   
6. Deploy an agent. See [Agent Execution Quick Start Guide](https://merlin-c2.readthedocs.io/en/latest/quickStart/quickstart.html#merlin-agent) for examples
7. Pwn, Pivot, Profit

   ```
   mkdir /opt/merlin;cd /opt/merlin
   wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
   7z x merlinServer-Linux-x64.7z
   sudo ./merlinServer-Linux-x64
   ./data/bin/merlinCLI-Linux-x64
   ```

## Mythic

Merlin can be integrated and used as an agent with the [Mythic](https://github.com/its-a-feature/Mythic) a 
collaborative, multi-platform, red teaming framework.

Visit the [Merlin on Mythic](https://github.com/MythicAgents/merlin) repository in the MythicAgents organization
to get started.

## Misc.

* To compile Merlin from source, view the [Custom Build](https://merlin-c2.readthedocs.io/en/latest/quickStart/quickstart.html#merlin-server) page
* For a full list of available commands:
   * [Main Menu](https://merlin-c2.readthedocs.io/en/latest/cli/menu/main.html)
   * [Listener Menu](https://merlin-c2.readthedocs.io/en/latest/cli/menu/listeners.html)
   * [Agent Menu](https://merlin-c2.readthedocs.io/en/latest/cli/menu/agents.html)
   * [Module Menu](https://merlin-c2.readthedocs.io/en/latest/cli/menu/modules.html)
* View the [Frequently Asked Questions](https://merlin-c2.readthedocs.io/en/latest/faq/faq.html) page
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
 