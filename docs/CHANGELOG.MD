# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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
