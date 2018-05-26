# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).


## [0.5.0] - 2018-05-26
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

## [0.1.4] - 2018-03-02
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