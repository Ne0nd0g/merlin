[![GoReportCard](https://goreportcard.com/badge/github.com/ne0nd0g/merlin)](https://goreportcard.com/badge/github.com/ne0nd0g/merlin)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/Ne0nd0g/merlin.svg)](https://github.com/Ne0nd0g/merlin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Ne0nd0g/merlin/total.svg)](https://github.com/Ne0nd0g/merlin/releases)
[![Slack](https://img.shields.io/badge/Slack-Sign--Up-blue.svg)](https://communityinviter.com/apps/merlin-go/merlin)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/Ne0nd0g/merlin?branch=dev&svg=true)](https://ci.appveyor.com/project/Ne0nd0g/merlin)

# Merlin (BETA)
Merlin is a cross-platform post-exploitation HTTP/2 Command & Control 
server and agent written in golang.

An introductory blog post can be found here:
https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a


[![asciicast](https://asciinema.org/a/166722.png)](https://asciinema.org/a/166722&speed=2)

## Getting Started
The quickest and easiest way to start using Merlin is download the
pre-compiled binary files found in the
[Releases](https://github.com/Ne0nd0g/merlin/releases) section. The
files are compressed into 7z archives and are password protected to
prevent Anti-Virus inspection when downloading. The password is
`merlin`.

## Install GO
In order to run Merlin from source, or to compile Merlin yourself, the
Go programing language must be installed on the system. However, if you
 just want to run a pre-compiled version, you _do not_ need to install
 Go.

Download and install GO: `https://golang.org/doc/install`

## Download Merlin Server
> It is recommended to download the compiled binaries from the
[Releases](https://github.com/Ne0nd0g/merlin/releases) section

>Ensure your GOPATH environment variable is
[set](https://github.com/golang/go/wiki/SettingGOPATH)

Download Merlin with Go

`go get github.com/Ne0nd0g/merlin`

If you want to use git instead of Go, merlin must be in your GOPATH i.e.
`$GOPATH/src/github.com/Ne0nd0g/merlin`

`cd $GOPATH/src/github.com/Ne0nd0g;git clone https://github.com/Ne0nd0g/merlin/`

## Run Merlin Server
Merlin Server can be run as a script or compiled and run as a standalone
 binary file.

`go run cmd/merlinserver/main.go`

## Compile Merlin Server
Compile Merlin into an executable using Make
`make server-windows` or `make server-linux` or `make server-darwin`

### Merlin Server Usage
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

## Merlin Server Commands
Merlin is equipped with a tab completion system that can be used to see
what commands are available at any given time. Hit double tab to get a
list of all available commands.

 Name   | Description
 ---    | ---
 agent   | Interact with agents or list agents
 banner | Print the Merlin banner
 exit   | Exit and close the Merlin server
 help   | Print help screen
 interact | Interact with an agent. Alias for Empire users
 quit   | Exit and close the Merlin server
 sessions | List all agents session information. Alias for MSF users
 use    | Use a function of Merlin (i.e modules)
 version | Print the Merlin server version
 ?      | Print help screen
 `*`    | Anything else will be execute on the host operating system

## Agent Commands
These are the commands to control an agent from the server. Tab
completion can be used to select an Agent's identifier.

 Name   | Description
 ---    | ---
 cmd   | Execute a command on the agent", "cmd ping -c 3 8.8.8.8"
 back   | Return to the main menu
 download | Download a file from the agent
 exit   | Exit and close the Merlin server
 help   | Print help screen
 info | Display all information about the agent
 kill | Instruct the agent to die or quit
 main | Return to the main menu
 quit   | Exit and close the Merlin server
 set | Set the value for one of the agent's options (alias, maxretry, padding, skew, sleep)
 show | Show information about a module or its options (show options or show info)
 upload | Upload a file to the agent
  ?      | Print help screen
  `*`    | Anything else will be execute on the host operating system

## Module Commands
These are the commands to configure and execute a module. Tab completion
 can be used to select options and agents.

 Name   | Description
 ---    | ---
 back   | Return to the main menu
 exit   | Exit and close the Merlin server
 help   | Print help screen
 main | Return to the main menu
 quit   | Exit and close the Merlin server
 reload | Reloads the module to a fresh clean state
 run | Run or execute the module
 set | Set the value for one of the module's options
 show | Show information about a module or its options (show options or show info)
 ?      | Print help screen
 `*`    | Anything else will be execute on the host operating system

### TLS Certificates
By default, Merlin will load server.crt and server.key from the
`data/x509/` directory. You must generate your own certificate pair and
place them in this directory.

### Third Party Libraries
The 3rd party libraries used with Merlin are kept in the _vendor_
directory. This project will default to using the library files in that
folder.

## Running Merlin Agent
The agent portion of Merlin should be run as a compiled binary file on
a target host.

> It is recommended to download the compiled binaries from the
[Releases](https://github.com/Ne0nd0g/merlin/releases) section

>Ensure your GOPATH environment variable is set!

Compile Merlin Agent into an executable

`make agent-windows` or `make agent-linux` or `make agent-darwin`

Merlin Agent can also be compiled without Make, using just go. To
compile Merlin Agent with your hard coded Merlin Server's address, so it
 doesn't have to specified on the command line, include `-ldflags
 -X main.url=https://acme.com:443/`

>Example: `go build -o merlinagent.exe -ldflags
"-X main.url=https://acme.com:443/" cmd/merlinagent/main.go`

Run Merlin Agent as script: `go run cmd/merlinagent/main.go`

### USAGE

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
