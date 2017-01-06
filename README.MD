
# Merlin
Merlin is a Command & Control toolset written in golang that operates over an HTTP/2 connection. Communications are passed between the server and agent using JSON messages.

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

## PowerShell
By default, all commands are executed on the victim using PowerShell and base64 commands.

`PS C:\> powershell.exe -w hidden -nop -Enc RwBlAHQALQBOAGUAdABBAGQAYQBwAHQAZQByAA==`

### TLS Certificates
By default, Merlin will load server.crt and server.key from the `data/x509/` directory. You must generate your own certificate pair and place them in this directory.
### Third Party Libraries
	github.com/fatih/color
	github.com/satori/go.uuid
	golang.org/x/net/http2
	github.com/mattn/go-sqlite3
	    * requires gcc
	    * Use tdm64-gcc or mingw-w64 for Windows and add its /bin directory to your path