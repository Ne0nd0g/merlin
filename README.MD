
# Merlin
Merlin is a Command & Control toolset written in golang that operates over an HTTP/2 connection. Communications are passed between the server and agent using JSON messages.

## Install GO
The Go programing language must be installed on the system hosting Merlin.

Download and install GO: `https://golang.org/doc/install`

## Running Merlin
Merlin can be run as a script or compiled and run as a standalone binary file.
>Ensure your GOPATH environment variable is set

Windows `set GOPATH=C:\Merlin`

*nix    `export GOPATH=/opt/Merlin`

3rd party libraries must be installed with:
```
go get golang.org/x/net/http2
go get github.com/fatih/color
go get github.com/satori/go.uuid
```

Run Merlin Server as a script: `go run merlinserver.go`

Compile Merlin into an executable: `go build -o bin\merlinserver.exe merlinserver.go`

### USAGE
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

## Server Commands
```

exit    Exit and close Merlin

help   Show Merlin help menu

quit    Exit and close Merlin

?      Show Merlin help menu
```

## Agent Commands
```
agent_cmd <agent id> <command>       A command to run on a remote agent

agent_control <agent id> <command>  Configure/Control a remote agent (not the host)
                [kill,]

agent_info <agent id>               Display all information for an agent

agent_list                          List agents

```

### TLS Certificates
By default, Merlin will load server.crt and server.key from the `data/x509/` directory. You must generate your own certificate pair and place them in this directory.
### Third Party Libraries
	github.com/fatih/color
	github.com/satori/go.uuid
	golang.org/x/net/http2
	github.com/mattn/go-sqlite3
	    * requires gcc
	    * Use tdm64-gcc or mingw-w64 for Windows and add its /bin directory to your path

Execute this command to install all dependencies:
`go get github.com/fatih/color github.com/satori/go.uuid golang.org/x/net/http2 github.com/mattn/go-sqlite3`

## Merlin Agent
The agent portion of Merlin should be run as a compiled binary file on a target host.

>Ensure your GOPATH environment variable is set

Windows `set GOPATH=C:\Merlin`

*nix    `export GOPATH=/opt/Merlin`

Compile Merlin Agent into an executable: `go build -o bin\merlinagent.exe merlin\agent\main.go`

Run Merlin Agent as script `go run merlin\agent\main.go`

### USAGE

```
  -debug
        Enable debug output
  -sleep duration
        Time for agent to sleep (default 10s)
  -url string
        Full URL for agent to connect to (default "https://127.0.0.1:443")
  -v    Enable verbose output
```