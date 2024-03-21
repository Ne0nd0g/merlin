# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 2.1.2 - 2024-03-21

### Fixed

- SOCKS listener was not properly handling data and connection status
  - Increased SOCKS job in/out channel size from 100 to 1,000
  - Fixed a bug where multiple SOCKS go routines were created instead of one
  - Updated `readSOCKSClient()` function to close the connection on any connection read error
  - Updated `processMessage()` to drop SOCKS jobs when the connection was already closed
  - Added `NewInfoWithID()` factory for SOCKS jobs information structures that keep the same Job ID for the connection lifetime

### Changed

- Upgraded the following libraries to their latest version
  - upgraded github.com/google/uuid v1.5.0 => v1.6.0
  - upgraded golang.org/x/net v0.21.0 => v0.22.0
  - upgraded golang.org/x/sync v0.5.0 => v0.6.0
  - upgraded google.golang.org/grpc v1.60.1 => v1.62.1
  - upgraded github.com/quic-go/quic-go v0.40.1 => v0.42.0

### Security

- Upgraded go-jose/v3 to v3.0.3 to address CVE-2024-28180
- Upgraded the protobuf library to v1.33.0 to address CVE-2024-24786

## 2.1.1 - 2024-01-04

### Added

- Added Qodana baseline file

### Changed

- Upgraded packages
 - `github.com/Ne0nd0g/merlin-message` to v1.3.0
 - `github.com/quic-go/quic-go` to v0.40.1
 - `google.golang.org/grpc` to v1.60.0
- Modified Dockerfile
  - Upgraded `ne0nd0g/merlin-base` v1.5.0 in Dockerfile
  - Changed `ENTRYPOINT` to execute a compiled binary instead of `go run` 
- Removed `GOGARBLE` environment variable from Makefile

## 2.1.0 - 2023-12-14

### Fixed

- [Issue 148](https://github.com/Ne0nd0g/merlin/issues/148) - Validate & encode gRPC messages to UTF-8

## 2.0.0 - 2023-11-05

### Added

- Peer-to-Peer Agent communications
- gRPC Server for [Merlin CLI](https://github.com/Ne0nd0g/merlin-cli)
  - Default interface/port is `127.0.0.1:50051` and default password is `merlin`
  - `-addr` the address to listen for gRPC connections from the Merlin CLI
  - `-password` the password for CLI RPC clients to connect to the Merlin server
  - `-secure` require client TLS certificate verification
  - `-tlsCA` TLS Certificate Authority file path to verify client certificates
  - `-tlsCert` TLS certificate file path for the Merlin server
  - `-tlsKey` TLS private key file path for the Merlin server
- Structured logging in JSON format to STDOUT using [log/slog](https://pkg.go.dev/log/slog) package
  - `-debug` enable debug output
  - `-extra` enable extra debug output (e.g., HTTP requests/responses)
  - `-trace` enable trace output to see stepping through functions
- New SMB/UDP/TCP listeners
  - Used to configure how the listener process Agent traffic
  - Listeners DO NOT bind to interfaces/ports on the Merlin server, used for Agent configuration/generation ONLY
- Delegate message types and functions for processing them
- Configurable listener authentication methods for Agent communications: OPAQUE & none
- Configurable listener transforms for Agent communications: aes, base64-byte, base64-string, hex-byte, hex-string, gob-base, gob-string, jwe, rc4, and xor
  - The last transform in the list **MUST** be `gob-base`
- GitHub Actions for building and testing the Merlin Agent

### Changed

- Refactored _some_ areas to align with DDD and SOLID to alleviate circular dependencies implementing peer-to-peer comms
  - Implemented base "entity" structures and "aggregates"
  - Implemented the "Repository" pattern for Agents, Delegates, Groups, Listeners, Servers
  - Implemented the "Services" patter for interacting with Agents, Listeners, & Base messages
- Configurable JWT key value for HTTP listeners
- Upgraded [quic-go](https://github.com/quic-go/quic-go) to v0.40.0
- The Minimum supported Go version is now 1.21
- Listeners are now handled by a UUID and no longer by a name as a string
- Moved the `build` string out of `main.go` and into `pkg/merlin.go`
- Removed PWNBoard from `main.go`
- Removed wiki documentation from `docs` to a new repository at https://github.com/Ne0nd0g/merlin-documentation
- Replaced `github.com/satori/go.uuid` with `github.com/google/uuid`
- Replaced `github.com/square/go-jose` with `github.com/go-jose/go-jose`
- Replaced `github.com/Ne0nd0g/merlin/pkg/messages` with `github.com/Ne0nd0g/merlin-message`
  - Removes the need to depend on or import the Merlin Server package

### Removed

- Removed the interactive CLI menu to [Merlin CLI](https://github.com/Ne0nd0g/merlin-cli)
  - Uses gRPC to communicate with the Merlin server

## 1.5.1 - 2023-03-08

### Added

- Documentation for proxying Agent DLL provided by @HuskyHacks in [PR 136](https://github.com/Ne0nd0g/merlin/pull/136)

### Security

- [PR 137](https://github.com/Ne0nd0g/merlin/pull/137) - Bump golang.org/x/text from 0.3.7 to 0.3.8 by dependabot
- [PR 138](https://github.com/Ne0nd0g/merlin/pull/138) - Bump golang.org/x/net from 0.0.0-20220708220712-1185a9018129 to 0.7.0 by dependabot
- [PR 139](https://github.com/Ne0nd0g/merlin/pull/139) - Bump golang.org/x/crypto from 0.0.0-20200709230013-948cd5f35899 to 0.1.0 by dependabot
- [PR 140](https://github.com/Ne0nd0g/merlin/pull/140) - Bump golang.org/x/net from 0.1.0 to 0.7.0 by dependabot

## 1.5.0 - 2022-07-20

### Added

- Added new SOCKS5 functionality
  - Use `socks start 9050` from the agent menu to start a SOCKS5 listener on port 9050 on the Merlin server

### Changed

- Go v1.18 is now the minimum supported version
- Upgraded [quic-go](https://github.com/lucas-clemente/quic-go/) to v0.28.0
- Upgraded [Go JOSE](https://github.com/square/go-jose) to v2.6.0
- Reduced the default PBES2 count for payload JWE encryption from 500,000 to 3,000
  - https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2

## 1.4.3 - 2022-07-09

### Fixed

- [Issue 129](https://github.com/Ne0nd0g/merlin/issues/129) - Added references to Docker image source

## 1.4.2 - 2022-04-14

### Added

- Server shows error when BOTH the agent and the server were not obfuscated with the SAME seed
  - [merlin-agent/15](https://github.com/Ne0nd0g/merlin-agent/issues/15)

## 1.4.1 - 2022-04-12

### Fixed

- [Issue 126](https://github.com/Ne0nd0g/merlin/issues/126) - Upgraded [quic-go](https://github.com/lucas-clemente/quic-go/) to v0.27.0 for Go 1.18 support

## 1.4.0 - 2022-04-02

### Added

- Added new `memory` command w/ associated API & documentation to read/write virtual memory for Windows agents
  - The `read` command will just read the specified number of bytes and return the results
  - The `write` command will just write the specified bytes without reading them first
  - The `patch` command will find a specified function, read the existing bytes, and then overwrite it with the provided bytes

## 1.3.1 - 2022-03-22

### Added

- Added [Garble](https://github.com/burrowers/garble) builds to the Make file
  - `windows-garble`, `linux-garble`, & `darwin-garble`
  - **THE AGENT MUST BE GARBLED WITH THE EXACT SAME SEED**
  - Specify the seed at build with `make linux-garble SEED=<your seed valuee>`

### Fixed

- Instructing an agent to exit removes it from the server and CLI

## 1.3 - 2022-02-17

### Changed

- Added the `Integrity` field to the agents.Agent and messages.SysInfo structures
- The agent menu `info` command now shows the agent's integrity level
  - Windows: `2`-Medium, `3`-High, `4`-System
  - All other OS: `3` - member of sudo group, `4` - running as root
- Dockerfile now uses [merlin-base](https://hub.docker.com/r/ne0nd0g/merlin-base) image

## 1.2.1 - 2022-01-10

### Fixed

- [merlin-agent/Issue 6](https://github.com/Ne0nd0g/merlin-agent/issues/6) - Message padding is now a random length instead of a fixed length

## 1.2.0 - 2021-12-12

### Added

- `rm` command to remove, or delete, files using native Go functions
- `runas` Windows command to create a process as another user with their password
- `ssh` Connect to a remote host over SSH and execute a command (non-interactive)
- `token` Windows command to interact with Windows Access Tokens
  - `make` Create a new token with a username and password; Unlisted `make_token` alias
  - `privs` List the current or remote process token privileges
  - `rev2self` Drop any created or stolen access token and revert to original configuration; Unlisted `rev2self` alias
  - `steal` Steal a token from another process; Unlisted `steal_token` alias
  - `whoami` Enumerate process and thread token username, logon ID, privilege count, token type, impersonation level, and integrity level
- New Agent API calls: `RM`, `RunAs`, `Token`

### Changed

- Previously all unknown commands were executed on the host operating system; We must now prefix commands with `!`  (e.g., `!whoami`)
- Updated [go-quic](https://github.com/lucas-clemente/quic-go/) library to v0.24.0

### Fixed

* [issue 116](https://github.com/Ne0nd0g/merlin/issues/116) - Fixed missing statement to enable verbose & debug output for the server component
* [issue 119](https://github.com/Ne0nd0g/merlin/issues/116) - Add specific agent ID instead of broadcast "F" agent ID

## 1.1.0 - 2021-08-5

### Added

- Incorporated a lot of changes by [r00t0v3rr1d3](https://github.com/r00t0v3rr1d3) & [deviousbanana](https://github.com/deviousbanana) from their [fork](https://github.com/r00t0v3rr1d3/merlin/tree/dev)
- Ctrl-C and DEL key won't exit the server without a confirmation prompt from https://github.com/r00t0v3rr1d3/merlin/commit/d5aafdb97b50e43ae9842d8f91659f65d18f60d4
- `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g., DHCP) from https://github.com/r00t0v3rr1d3/merlin/commit/42a12af99610e439721cbd095a2d55523e7cbc94
- Agent struct and agent `info` command contain `Process` name from https://github.com/r00t0v3rr1d3/merlin/commit/cbf875427123e6a58a528d0e38a692c2308f09c9 
- Added the `kill` command to kill a running process by its process ID (PID)
- Added a calculated "LAST CHECKIN" column to the `sessions` command and the Agent menu `info` command
- Added the "PROCESS" column to the `sessions` command
- Added a shortcut `c` command for `clear` on the Agents menu to remove any jobs from the queue
- Replaced the `exit` command with `quit` to instruct the Merlin server to quit running
- The `sessions` and `interact` commands are available from every menu
- Filter the help and tab-completable list of commands to only show those available for the Agent's operating system
- Added additional aliases for command in the Agent's menu
  - `c` for `clear`
  - `assembly` for `execute-assembly`
  - `pe` for `execute-pe`
  - `shinject` for `execute-shellcode`
  - `ipconfig` for `ifconfig`
  - `exec` for `run`
- Added `jobs` command to main menu to show jobs for all agents
- Added `queue` command to main menu to queue up jobs for one agent, all agents, or an agent that hasn't registered yet
- Added a `note` command to the agent menu
- Added a `clear` command to the main menu to remove jobs for ALL agents that haven't been sent
- Added a `group` command that adds agents to groups for bulk command processing
  * Usage: `group add <agentID> <groupName>`
  * Usage: `group remove <agentID> <groupName>`
  * Usage: `group list`
  * Usage (from an agent's menu): `group add <groupName>`
- Added PwnBoard integration from [hulto](https://github.com/hulto)
- Added `sdelete` command to securely delete a file
- Added `touch`, alias is `timestomp`, command that matches the destination file's timestamps with source file
- Added `ps` command that returns a process listing for Windows agents only
- Added `netstat` that displays network connection for Windows agents (tcp, tcp6, udp, udp6)
- Added Windows only `pipes` command to list named pipes
- Added Windows only `uptime` command to print the target system's uptime
- Added `env` command: View and modify environment variables. "set" will create a new variable if it didn't exist
  * Usage: `env showall`
  * Usage: `env get PATH`
  * Usage: `env set CUSTOM "my desired value"`
  * Usage: `env unset HISTFILE`

### Changed

- The command to instruct a running agent to quit was changed from `kill` and is now `exit`
- Restructured the menu system into its own directory at `pkg/cli/menu`
- Changed the `interact` command to `configure` for the listener menu
- Removed the `set` command from the Agent menu in favor of just calling the command directly (e.g., `set killdate` -> `killdate`)
- Renamed API functions to remove any that started with "SET"
- Moved core functions to a child in the `cli` directory
- Removed `Type` and added `Command` to jobs table

## 1.0.1 - 2021-05-29

### Fixed

- [Issue 107](https://github.com/Ne0nd0g/merlin/issues/107) - RunModule() tasking uses `run` instead of removed `cmd`

## 1.0.0 - 2021-04-18

### Changed

- Added `main.go` to project root so that the Merlin server is compiled when retrieved with `go get`
- Change Makefile to only support building and packaging the server
- Updated Dockerfile

### Removed

- Removed all agent code from `pkg/agent`
- Removed all programs from `cmd` (e.g., `cmd/merlinagent`) to their own GitHub repository
- Removed User functions from opaque package to the Agent codebase
- Removed `Invoke-Melrin` and `merlin.js` from codebase completely

## 0.11.0 - 2021-04-17

### Added

- Added `nslookup` command to execute a DNS query using native Go
- Added [go-clr](https://github.com/Ne0nd0g/go-clr) for in process .NET Common Language Runtime (CLR)
  - `load-assembly` to load a .NET assembly into memory
  - `invoke-assembly` to execute a previously loaded .NET assembly
  - `list-assemblies` to list previously loaded .NET assemblies
- Added `memfd` command to run Linux executables in-memory as an anonymous file
- Upgraded go-quic package to support Go v1.16
- Added `SetWaitTime` and `SetMaxRetry` function to agents package to be called from the API package

### Fixed

- Fixed issue when sleep time was increased and all subsequent JWTs were expired by updating sleep time on server first

## 0.10.0 - 2021-02-13

### Added

- Added `windows/x64/go/exec/createProcess` extended module with redirected STDOUT/STDERR over anonymous pipes
- Added `windows/x64/go/exec/donut` extended module that leveraged [go-dounut](https://github.com/binject/go-donut)
- Added `windows/x64/csharp/misc/SharpGen` extended module that leverages [SharpGen](https://github.com/cobbr/SharpGen)
  - Requires [.NET Core 2.1 SDK](https://dotnet.microsoft.com/download/dotnet-core/2.1) to be manually installed by the operator
- Added `execute-assembly`, `execute-pe`, and `sharpgen` commands to Agent menu
- Added `ExecuteAssembly`, `ExecutePE`, and `SharpGen` functions to Agent API
- New Jobs structure so that multiple jobs and results can be sent between client and server during a single interaction
- Job processing checks to ensure returned results have a valid request token and had not previously completed
- Created constants for message types for easier comparison and switching
- Added a new `jobs` command to view created and sent jobs
- Added a new `clear` command to remove any jobs that have not been sent to the agent
- Added `killdate`, `maxretry`, `useragent`, `padding`, `skew` to Merlin Agent command line arguments and Makefile
- Added checks to OPAQUE handling to ensure resiliency if server is not available or has an error during registration
- Added Makefile `agent-windows-debug` build target to enable viewing verbose and debug messages
- Added Mythic client so [Merlin](https://github.com/MythicAgents/merlin) agent can be used with the [Mythic](https://github.com/its-a-feature/mythic) Framework

### Changes

- All commands typed into the `Merlin»` are immediately parsed with [go-shellwords](https://github.com/mattn/go-shellwords)
- Removed `go-shellwords` processing from Agent API functions CD, Download, Upload, and LS
- Modified agent structure to contain an input and out job channel
- Changed Agent go routine from messageHandler to function that continuously checks the job channel
- Job results are returned when the agent checks in again, not immediately after executed
- Moved OPAQUE functions to its own package at `pkg/opaque`
- Reduced base message payload types to just opaque, jobs, and checkin; Jobs payload now contains all other types
- Removed argument parsing from Agent's exec command. All parsing is done server side before being sent to the agent
- Removed RSA key exchange since it wasn't being used for anything
- Moved functions that output tables to the agent API that returns rows; CLI package prints them
- Removed CLI completer functions from `pkg/agents` and implemented functionality in agent API and CLI package
- Restructured Merlin Agent code into multiple go files
- Created generic MerlinClient interface to facilitate using different protocols
- Changed HTTP server timeout from 10 seconds to 30 seconds
- Changed the `shell` command to actually use the operating system's default shell
- Changed the old `cmd` & `shell` commands to just the `run` which executes the program directly without a shell

## Removed

- Removed the `cmd` command from the Agents menu

## 0.9.1 - 2020-09-23

### Fixed

- Modules were not sending the first value from the modules commands section
- [Pull 97](https://github.com/Ne0nd0g/merlin/pull/97) - Incorrectly validated the module and agent platforms when the agent was set to "all"

## 0.9.0 - 2020-09-13

### Added

- Incorporated a fork of `github.com/CUCyber/ja3client` allowing the Merlin agent to establish TLS connections from a JA3 signature
- Added `ja3` to agent.New() function
- Added `-ja3` to agent command line arguments and JA3 to Make file for hard coding initial signature
- Added `PSK=` to Make file
- Added `set ja3` to Agent menu allowing operators to change TLS client profile at any time
- Created new `merlinClient` interface to handle abstract http clients and changed the Agent.Client to that interface
- Updated Dockerfile to support Go modules
- Added support for plain-text HTTP/1.1 (http) and plain-text HTTP/2.0 (h2c)
- Increased initial JWT lifetime from 10 seconds to 60 seconds
- BASH module `linux\x64\bash\exec\bash.json` to run a single BASH command across all agents
- PowerShell module `windows\x64\powershell\exec\powershell.json` to run a single PowerShell command across all agents
- macOS Orchard module `darwin\x64\javascript\enumeration\orchard.json` a JavaScript for Automation (JXA) tool to do Active Directory enumeration
- macOS HealthInspector module `darwin\x64\javascript\enumeration\healthinspector.json` a JXA situational awareness helper by simply reading specific files on a filesystem
- macOS Bifrost module `darwin\x64\objective-c\kerberos\bifrost.json` an Objective-C library and console to interact with Heimdal APIs for macOS Kerberos
- macOS Venator module  `darwin\x64\python\enumeration\venator.json` a python tool used to gather data for proactive detection of malicious activity on macOS devices
- macOS SwiftBelt module `darwin\x64\swift\enumeration\swiftbelt.json` A MacOS enumerator similar to @harmjoy's Seatbelt
- Added `unset` command to modules to reset an option to nil
- Job result messages now include the agent ID
- Added new Listeners menu to create or remove multiple agent listeners per running Merlin Server instance
- Added new `servers` and `listeners` packages to handle new Listeners menu
- A single listener can now handle multiple URLS instead of just `/`
- Can enable/disable verbose and debug output from CLI main menu with `set vervose true`
- Added API packages for agents, listeners, modules, and messages to separate the CLI from the server
- Added a channel for user messages that the CLI reads from and then prints them to STDOUT
- Added 4 modules from the D(COM) V(ulnerability) S(canner) Framework to `windows\x64\powershell\lateral\dcom"`
- Added Sphinx documentation to `docs\` to replace GitHub wiki with ReadTheDocs

## Fixed

- Catch errors returned when starting a server (i.e insufficient privileges to bind to a port)
- hq listener would fail when in-memory x.509 certificates were used
- Invoke-M.i.m.i.k.a.t.z module points to the updated version of M.i.m.i.k.a.t.z (2.2.0) in the Empire 3.0 repository
- [Issue 88](https://github.com/Ne0nd0g/merlin/issues/88) - Set option will now take all arguments after a space
- Added module type to LinEnum, MimiPenguin, and SwapDigger
- [Issue 71](https://github.com/Ne0nd0g/merlin/issues/71) - Run a module against all agents

## Changed

- Made module variables case-insensitive. Values will still match input case
- Moved `GetTLSCertificates()` and `CheckInsecureFingerprint()` to utils package
- Moved JWT create, validate, decrypt functions to the utils package
- Moved Agent handling code to a new handlers package
- All packages _should_ be sending messages to the CLI through the message API package
- Upgraded gopaque library to v0.1.0
- Upgraded kyber library to v3.0.12

## Removed

- Removed all command line arguments from Merlin Server executable in favor of run-time Listeners menu

## Security

- OPAQUE go library used static decryption key and allowed EnvU to be decrypted without the correct password (PwdU)
  [gopaque - Issue 2](https://github.com/cretz/gopaque/issues/2)
- Symmetric encryption key was use with OPAQUE User Authentication instead of OPAQUE password (PwdU)

## 0.8.1 - 2019-10-08

### Fixed

- [Issue 77](https://github.com/Ne0nd0g/merlin/issues/77) - Set server and agent log files with `0640` permissions

## 0.8.0 - 2019-08-20

### Added

- Network requests and responses are now encrypted in to a JWE
- Password Based Authenticated Key Exchange (PAKE) using OPAQUE technique
- Server and agent have new pre-shared key (psk) command line flag
- All network requests now contain an encrypted JWT in an Authorization header that are only valid for the agent's lifetime
- RSA keys are exchanged between server and agent, but not currently used
- Added `PSK=` to Make file so the binaries can be hard coded with the PSK
- Added Merlin server identification tool dubbed PRISM
- Added gcflags & asmflags trimpaths to remove _some_ of the file path strings in output agent binary files
- Added http/1.1 support
- Added support for user defined HTTP proxy with agent `-proxy` command line flag; Only works with HTTP/1.1
- Added `PROXY=` to Make file so the binaries can be hard coded with the proxy
- Added PRISM application to detect a Merlin server
- Added in CLI option to set HTTP Host header for domain fronting
- [Pull 72](https://github.com/Ne0nd0g/merlin/pull/72) - Added a Linux module that will hide the Merlin process from tools that walk the /proc filesystem by @ForensicITGuy
- [Pull 73](https://github.com/Ne0nd0g/merlin/pull/74) - Added 5 Linux evasion and persistence modules by @ForensicITGuy
- [Pull 76](https://github.com/Ne0nd0g/merlin/pull/76) - Prompt user to confirm exit or quit by [Daniel Roberson](https://github.com/droberson)

### Fixed

- [Pull 74](https://github.com/Ne0nd0g/merlin/pull/74) - Fixed issued that would crash the agent if the skew was set to 0 by @alexbires
- [Issue 54](https://github.com/Ne0nd0g/merlin/issues/54) - Prompt to exit server when user types "quit" or "exit"

### Changed

- Replaced JSON encoding with Go's gob encoding format
- Server does not receive agent information/configuration until after password authentication/payload encryption
- Base messages now contain a token; used to send an agent an encrypted JWT
- agent.New() requires the url, psk, and proxy settings
- agent.New() can return an error
- agent.Run() does not take a url anymore, it is part of the Agent structure
- agent.Run() can return an error
- Server & Agent log file directory permissions changed to 0750
- Server & Agent log file permissions changed to 0640

### Removed

- Removed http server's check to only allow HTTP/2 traffic so that HTTP/1.1 traffic can be supported
- Removed Vendor folder updated project to use Go Modules in go.mod

## 0.7.1 - 2019-04-21

### Fixed

-[Issue 69](https://github.com/Ne0nd0g/merlin/issues/69) - Error with modules missing type definition
-[Issue 70](https://github.com/Ne0nd0g/merlin/issues/70) - Error parsing a shellcode file containing raw bytes

## 0.7.0 - 2019-04-11

### Added
- [Pull 48](https://github.com/Ne0nd0g/merlin/pull/48) - Added `ls` command to agent & agent menu. Uses go code native to Merlin instead of executing `ls` or `dir` binary
- New `NativeCmd` message struct for commands native to Merlin
- [Pull 49](https://github.com/Ne0nd0g/merlin/pull/49) - Added tests for agent package and new `/test` directory for test HTTP server
- [Pull 50](https://github.com/Ne0nd0g/merlin/pull/50) - Adds a killdate option to agents
  - Added `set killdate` to Merlin Server agent menu and information table so that it can be changed from the server.
- [Pull 51](https://github.com/Ne0nd0g/merlin/pull/51) - Adds a Go native `minidump` module for Windows agents to create and receive a minidump file of a specified process (requires elevation)
  - windows/x64/go/credentials/minidump.json module (@C__Sto)
  - getProcess Function to exec_windows.go
  - sePrivEnable Function to exec_windows.go
  - MinidumpFile struct to modules.go
  - Module struct to messages.go
  - agent_windows_test.go to test miniDump functionality 
- [Pull 58](https://github.com/Ne0nd0g/merlin/pull/58) - Added feature to generate in-memory TLS certificates one is not provided
  - Adds new `pkg/utils/tls.go` package to generate TLS certificates
  - Updated Merlin server log to include certificate information
  - Test case for TLS certificate generation
- [Pull 60](https://github.com/Ne0nd0g/merlin/pull/60) - Added `pwd` and `cd` command to agent & agent menu. 
  - Uses go code native to Merlin instead of executing system binaries or access the system's CLI.
- merlin.dll contains a DllMain function and a function named Magic to instantiate a Merlin agent
    - DllMain does nothing
- Added exported function named Merlin to merlinagentdll/main.go to take in a C *char and convert to Go string
- Shellcode Reflective DLL Injection (sRDI) module windows/x64/go/exec/sRDI
- Shellcode injection module at windows/x64/go/exec/shellcode provides same functionality as execute-shellcode from Agent menu
- "extended" module types that call Go code from the pkg/modules directory
- [Pull 64](https://github.com/Ne0nd0g/merlin/pull/64) - Added in Dockerfile by Alex Flores (@audibleblink)

### Fixed
- [Pull 57](https://github.com/Ne0nd0g/merlin/pull/57) - Resolved broken JSON does not increment failedCheckin counter on Merlin agent

### Changed
- Changed SHA1 library to SHA256 and checks from http2.go for publicly distributed Merlin Server test certificate
- Moved execute-shellcode functionality to pkg/modules/shellcode
- merlin.c contains DllMain and exported Magic function
- Merlin Server uses exit code 0 after printing usage information

### Removed
- Removed publicly distributed certificates from repository see [Pull 58](https://github.com/Ne0nd0g/merlin/pull/58).
- Removed "main" and "ReflectiveLoader" functions from merlin.dll/merlin.c

## 0.6.8 - 2019-01-26

### Added
- The `status` command while in the agent menu to see if agent is Active, Delayed, or Dead
- Messages printed to the CLI now include a UTC timestamp
- Added Merlin version number and new agent checkins to Merlin Server log file

### Fixed
- Formatting error placing time stamp and message in wrong spot in the Merlin Server log file
- Error checking in logging.go
- Server shutdown was not actually being logged

## 0.6.7 - 2019-01-22

### Added
- [Pull 45](https://github.com/Ne0nd0g/merlin/pull/45) - Added a module for Python-based SOCKS proxying (@klusitc)

### Changed
- Modified http2.go to remove `[+]` & `[!]` from shell command results printed to the terminal
- Modified agents.go so the log files and agent info contain time in [RFC 3339](https://tools.ietf.org/html/rfc3339) compliant UTC
- Replaced SHA-1 hash with SHA-256 in log file when using upload command
- Updated agents.go with missing error checking

## 0.6.6 - 2019-01-21

### Changed

- [Pull 43](https://github.com/Ne0nd0g/merlin/pull/43) - Gives users the ability to dynamically
assign the callback URL variable at compile time by setting the URL= var in the make command by Alex Flores (@audibleblink)

### Fixed
- [Pull 44](https://github.com/Ne0nd0g/merlin/pull/44) Fixes case-sensitive autocompletion of `agent`
  on the module menu (@audibleblink)

## 0.6.5 - 2019-01-10

### Fixed
- [Issue 41](https://github.com/Ne0nd0g/merlin/issues/41) Error when downloading a file using a path containing a space

### Changed
- Updated `download` command to correctly parse a remote file path containing a space
- Removed `data\x509` from .gitignore so that certificates WILL be distributed when cloning the repository to facilitate easy testing

## 0.6.4 - 2019-01-01

### Added
- Execute shellcode inside current process (Windows only)
  - `execute-shellcode self <SHELLCODE>` command from agent menu
  - executeShellcode function added to agents package
  - ExecuteShellcodeSelf function added to agents/exec.go
- Execute shellcode inside remote process (Windows only)
  - `execute-shellcode remote <PID> <SHELLCODE>` command from agent menu
  - ExecuteShellcodeRemote function added to agents/exec.go
- Execute shellcode inside remote process using RtlCreateUserThread (Windows only)
  - `execute-shellcode rtlcreateuserthread <PID> <SHELLCODE>` command from agent menu
  - ExecuteShellcodeRtlCreateUserThread function added to agents/exec.go
- Execute shellcode inside remote process using QueueUserAPC (Windows only)
  - `execute-shellcode userapc <PID> <SHELLCODE>` command from agent menu
  - **WARNING**: very unstable and will likely crash process; working on stable implementation
  - Command intentionally not added to tab completion menu while unstable
- parseHex function added to cli package
- parseShellcodeFile function added to cli package
- `golang.org/x/sys/windows` to vendor folder
- Shellcode struct to messages package
- .gitattributes file to detect project as Go

### Changed
- Updated github.com/mattn/go-shellwords/ package in vendor

## 0.6.3 - 2018-10-24
### Added
- Added "shell" command to agent menu
- Added `-w` compile time link flag to omit the DWARF symbol table
- Added additional `-X` compile flag to set the build in the Agent package

### Changed
- [Issue 26](https://github.com/Ne0nd0g/merlin/issues/26) Updated Makefile to remove .dmg file extension for Darwin
- [Issue 23](https://github.com/Ne0nd0g/merlin/issues/23) Error when using upload command without specific arguments
- [Issue 28](https://github.com/Ne0nd0g/merlin/issues/28) Updated MimiPenguin module to use new path to download mimipenguin.sh
- Modified `cmd/merlinagentdll/main.go` Global variable from `URL` to `url` for consistency across all packages

## 0.6.2 - 2018-09-02
### Changed
- Added Twitter badge to README
- Configured agent status check in to use a go routine
- Removed unnecessary global variables from agent.go
- Documented agent.Agent struct fields
- Added "initial" field to agent.Agent struct

### Fixed
- [Issue 23](https://github.com/Ne0nd0g/merlin/issues/23) Error writing an agent log entry when agent was set to 'all'
- Out of range error when setting module options in Run function

## 0.6.1 - 2018-08-11
### Added
- Added Merlin Cheat Sheet to docs/MerlinCheatSheet.pdf
- Added module for GhostPack's Seatbelt
- Added module for GhostPack's SafetyKatz
- Added module for GhostPack's SharpDump
- Added module for GhostPack's SharpRoast
- Added module for GhostPack's SharpUp
- Added Compiler-CSharp module
- Added Inveigh module

### Changed
- Make file extracts version number from pkg/merlin.go

## 0.6.0 - 2018-07-29
### Added
- Added support for QUIC protocol version Q39 to both Server and Agent
- Added `-proto` command line flag for both Server and Agent
- Added Server struct with New and Run methods to http2 lib
- Added `github.com/lucas-clemente/quic-go` & supporting libs to Vendor
- Added check for publicly distributed Merlin x.509 testing certificate
- Added Job struct, GetMessageForJob function, and AddJob function to agents.go
- Added GetAgentStatus function to agents.go
- Added proto and status to table output for agent or session information
- Added RemoveAgent fuction to agents.go
- Added remove command to main menu to remove DEAD agents
- Added info command to module menu as a shortcut for show info
- Added data/html to server distrobution files
- Added agent-javascript to Make file to update version and build info

### Changed
- Server CLI starts first, then web server
- Renamed http2 `handler` function to `agentHandler`
- Agent struct to have `Client` and `UserAgen` fields
- Default User-Agent for client connections to `Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36`
- Renamed agent `getH2WebClient` function to `getClient`
- channel type to Job for agent struct in agents.go
- agents.StatusCheckIn to return error type
- QUIC idle timeout to 1 week
- agent struct to export initial and status check in values
- agent struct to have communication protocol value
- AgentInfo struct to have proto and embeded SysInfo struct
- Updated tablewriter library to latest version
- Updated merlin.js agent to use new embeded SysInfo struct
- Updated Make file to output files in folder of the build number
- Updated MerlinAgentDLL main.go functions to use correct params
- Merlin Server listens on 127.0.0.1 by default

### Removed
- Removed AddChannel function from agents.go

## 0.5.4 - 2018-07-17
### Added
- Added Get-ScheduledTaskComHandler module
- Added Invoke-PowerThIEf module

## 0.5.3 - 2018-07-04
### Fixed
- Fixed #21 by changing `strings.TrimRight()` to `strings.TrimSuffix()`

## 0.5.2 - 2018-06-13
### Added
- Added 4 modules from @HarmJ0y's Discretionary ACL Modification Project (DAMP)
- Added Add-RemoteRegBackdoor module
- Added Get-RemoteCachedCredential module
- Added Get-RemoteLocalAccountHash module
- Added Get-RemoteMachineAccountHash module

## 0.5.1 - 2018-05-26
### Added
- Added DSCompromised-Configure-Victim module
- Added Create-HotKeyLN module
- Added Get-OSTokenInformation module
- Added Invoke-WMILM module

## 0.5.0 - 2018-05-26
Version numbers changed drastically to start following semantic versioning
### Added
- Module reload command to instantiate a new, clean object
- windows/x64/powershell/privesc/psgetsystem.json module
- linux/x64/bash/credentials/MimiPenguin.json module (@ahhh)
- linux/x64/bash/troll/Prank.json module (@ahhh)
- windows/x64/powershell/persistence/Invoke-ADSBackdoor.json module (@ahhh)
- Merlin agent DLL
- Invoke-Merlin PowerShell script
- Package compiled agents with releases in data/bin directory

### Changed
- Updated existing linux modules to use the /bin/sh shell
- Updated module template file base.json to include _credits_
- Make file to support compiling DLL
- cmd/merlinagent/main.go into several packages and struct in
pkg/agent/main.go
- Renamed pkg/agent/agent.go to pkg/agent/exec.go
- Version numbers to follow semantic versioning
- Added "agent" to the table for a module's options (@0xada4d)
- Added _credits_ to modules.go
- Updated main README.MD

### Fixed
- Null use command caused shell to exit
- Module set option verbose output to new value instead of original
- Agent upload error message invalid memory address or nil pointer dereference

## 0.1.4 - 2018-03-02
### Added
- Time skew to sleep by @ahhh
- IP address information from agents by @ahhh
- MIPS and ARM agent compile instructions to Make file by @twigatech
- File upload from server to agent by @twigatech
- .gitignore for data directory by @twigatech
- Merlin JavaScript Agent
- Merlin JavaScript Agent test page in `data/html`
- CORS header "Access-Control-Allow-Origin: *" to every response
- Server handling for OPTIONS request to facilitate JavaScript XHR requests
- Thanks to JetBrains for an open source license
- This CHANGELOG
- Module support
- Multiple Windows and Linux modules
- Module README on how to create a module
- Execute commands on the host operating system from Merlin prompt
- Execute module on "all" agents

### Changed
- Menu system from one long command to multiple menus
- Merlin Server from 1 large file to multiple library files in `pkg`
- Make file instructions for Merlin version number
- Agent command execution to send back argument processing errors


## 0.1.3 - 2017-12-17
### Added
- First public release

## 0.1.2 - 2017-01-13
### Added
- Makefile to make building the server and agent easier
- New libraries to help with displaying information in formatted tables
- Tab completion for commands issued on the server

### Changed
- Agent to include a random padding of up to 4096 bytes per message to
 help prevent detection based off consistent message size.


## 0.1.0 - 2017-06-10

This release marks a stable BETA version of Merlin. Both the server and
the agent cross-compile to Windows, Linux, and MacOS. The 64 bit version
 of the agent binaries for all 3 platform can be found in data\bin. The
32 bit binaries are not provided, but could be compiled if you desire.
Check the README in the data\bin directory. To run this release,
download Merlin_v0.1Beta.zip and unzip the contents. Next, download the
applicable binary for your platform (i.e. merlinserver_windows_x64.exe)
and place it in the root of that unzipped folder. The binary can be run
from the command line. Alternatively, Merlin can be run directly as a go
 script with go run cmd\merlinserver.go.
