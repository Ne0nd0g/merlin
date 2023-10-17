/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package rpc

import (
	// Standard
	"context"
	"fmt"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	pb "github.com/Ne0nd0g/merlin/pkg/cli/rpc"
)

/* RPC FUNCTIONS TO TASK AGENTS */

// Any is used to execute arbitrary Agent commands. The first argument is the command to execute, and the remaining
// arguments are passed to the command.
// args[0] = command to execute (e.g., connect, download)
// args[1: ] = arguments to pass to the command
func Any(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the Any RPC call requires at least one argument, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.Any(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// CD is used to change the agent's current working directory
// args[0] = the directory path to change to
func CD(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.CD(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// CheckIn creates an AgentInfo job that forces the Agent to send data back to the server
func CheckIn(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.CheckIn(context.Background(), &pb.ID{Id: id.String()}))
}

// CMD is used to send a command to the agent to run a command or execute a program
// args[0] = "cmd"
// args[1:] = program and arguments to be executed on the host OS of the running agent
// Used with `cmd` and `shell` commands as well as through "standard" modules
func CMD(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) <= 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the CMD RPC call requires at least two arguments, have: %+v", args))
		return
	}
	return buildMessage(service.merlinClient.CMD(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Connect instructs an Agent to disconnect from its current server and connect to the new provided target
// Args[0] = the target address or URI to connect to
func Connect(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the Connect RPC call requires at least one argument, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.Connect(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Download is used to download the file through the corresponding agent from the provided input file path
// args[0] = the file path to download
func Download(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the Download RPC call requires one arguments, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.Download(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// ENV is used to view or modify a host's environment variables
// args[0] = the action to take (e.g., get, set, showall, unset)
// args[1] = the name of the environment variable to modify
// args[2] = the value to set the environment variable to
func ENV(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the Download RPC call requires one arguments, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.ENV(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// ExecuteAssembly calls the donut module to create shellcode from a .NET 4.0 assembly and then uses the CreateProcess
// module to create a job that executes the shellcode in a remote process
// args[0] .NET assembly File bytes as Base64 string
// args[1] .NET assembly arguments
// args[2] SpawnTo path
// args[3] SpawnTo arguments
func ExecuteAssembly(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 2 {
		msg = message.NewErrorMessage(fmt.Errorf("the ExecuteAssembly RPC call requires at least two arguments, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.ExecuteAssembly(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// ExecutePE calls the donut module to create shellcode from PE and then uses the CreateProcess
// module to create a job that executes the shellcode in a remote process
// args[0] PE file bytes as Base64 string
// args[1] PE arguments
// args[2] SpawnTo path
// args[3] SpawnTo arguments
func ExecutePE(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 2 {
		msg = message.NewErrorMessage(fmt.Errorf("the ExecutePE RPC call requires at least two arguments, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.ExecutePE(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// ExecuteShellcode calls the corresponding shellcode module to create a job that executes the provided shellcode
// args[0] shellcode bytes as Base64 string
// args[1] Shellcode execution method (e.g., self, remote, rtlcreateuserthread, userapc)
// args[2] PID to inject shellcode into (only used with remote, rtlcreateuserthread, and userapc methods)
func ExecuteShellcode(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the ExecuteShellcode RPC call requires at least one argument, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.ExecuteShellcode(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Exit instructs the agent to quit running
func Exit(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Exit(context.Background(), &pb.ID{Id: id.String()}))
}

func IFConfig(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.IFConfig(context.Background(), &pb.ID{Id: id.String()}))
}

// InvokeAssembly executes an assembly that was previously loaded with the load-assembly command
// args[0] = the assembly name to execute
// args[1: ] = arguments to pass to the assembly
func InvokeAssembly(id uuid.UUID, args []string) (msg *message.UserMessage) {
	if len(args) < 1 {
		msg = message.NewErrorMessage(fmt.Errorf("the InvokeAssembly RPC call requires at least one argument, have (%d): %+v", len(args), args))
		return
	}
	return buildMessage(service.merlinClient.InvokeAssembly(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// JA3 is used to change the Agent's JA3 signature
// args[0] = the JA3 signature to change to
func JA3(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.JA3(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// KillDate configures the date and time that the agent will stop running
// args[0] = the date and time to stop running
func KillDate(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.KillDate(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// KillProcess tasks an agent to kill a process by its number identifier
// args[0] = the process ID to kill
func KillProcess(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.KillProcess(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// LinkAgent tasks a parent agent to connect to and link a child agent
// args[0] = the link method (e.g., add|list|remove|refresh|tcp|udp|smb)
// args[1] = method arguments
func LinkAgent(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.LinkAgent(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// ListAssemblies instructs the agent to list the .NET assemblies that are currently loaded into the agent's process
// .NET assemblies are loaded with the LoadAssembly call
func ListAssemblies(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.ListAssemblies(context.Background(), &pb.ID{Id: id.String()}))
}

// Listener interacts with Agent listeners used for peer-to-peer communications
// args[0] = the listener method (e.g., list|start|stop)
// args[1:] = method arguments; [protocol] [address]
func Listener(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Listener(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// LoadAssembly instructs the agent to load a .NET assembly into the agent's process
// args[0] is a Base64 encoded string of the assembly bytes
// args[1] is the assembly name or alias
// args[2] is the calculated SHA256 hash of the assembly
func LoadAssembly(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.LoadAssembly(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// LoadCLR loads the .NET Common Language Runtime (CLR) into the agent's process.
// .NET assemblies can subsequently be loaded with the LoadAssembly call and executed with the InvokeAssembly call
// args[0] = the .NET CLR version to load (e.g., v2.0.50727, v4.0.30319, or v4.0)
func LoadCLR(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.LoadCLR(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// LS uses native Go to list the directory contents of the provided path
// args[0] = the directory path to list
func LS(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.LS(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// MaxRetry configures the amount of times an Agent will try to check in before it quits
// args[0] = the number of times to retry
func MaxRetry(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.MaxRetry(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Memory interacts with virtual memory on the operating system where the agent is running
// args[0] = the memory method (e.g., read|write|patch)
// args[1:] = method arguments
func Memory(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Memory(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// MEMFD run a linux executable "from memory"
// args[0] = the executable as a base64 encoded string
// args[1:] = arguments to pass to the executable
func MEMFD(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.MEMFD(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Netstat is used to print network connections on the target system
// args[0] = -p OPTIONAL
// args[1] = the protocol to filter on (e.g., tcp or udp) OPTIONAL
func Netstat(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Netstat(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// NSLOOKUP instructs the agent to perform a DNS query on the input
// args[0:] = the host name or IP address to query
func NSLOOKUP(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Nslookup(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Padding configures the maximum size for the random amount of padding added to each message
// args[0] = the maximum size of the padding
func Padding(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Padding(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Pipes enumerates and displays named pipes on Windows hosts only
func Pipes(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Pipes(context.Background(), &pb.ID{Id: id.String()}))
}

// PS displays running processes
func PS(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.PS(context.Background(), &pb.ID{Id: id.String()}))
}

// PWD is used to print the Agent's current working directory
func PWD(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.PWD(context.Background(), &pb.ID{Id: id.String()}))
}

// RM removes or deletes a file
// args[0] = the file path to remove
func RM(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.RM(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// RunAs creates a new process as the provided user
// args[0] = the domain\username to run the program as
// args[1] = the password for the provided user
// args[2] = the program to run
// args[3:] = the arguments to pass to the program
func RunAs(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.RunAs(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// SecureDelete securely deletes supplied file
// args[0] = the file path to securely delete
func SecureDelete(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.SecureDelete(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// SharpGen generates a .NET core assembly, converts it to shellcode with go-donut, and executes it in the spawnto process
// args[0] = the .NET Core C# code, as a string, to compile
// args[1] = the SpawnTo process to inject the shellcode into
// args[2] = the arguments to pass to the SpawnTo process (optional)
func SharpGen(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.SharpGen(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Skew configures the amount of skew an Agent uses to randomize checkin times
// args[0] = the amount of skew to use
func Skew(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Skew(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Sleep configures the Agent's sleep time between checkins
// args[0] = the amount of time to sleep
func Sleep(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Sleep(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Socks creates a TCP listener on the provided port and forwards SOCKS5 traffic to the provided agent
// args[0] = method
// args[1] = interface:port
// args[2] = agent ID
func Socks(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Socks(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// SSH executes a command on a remote host through the SSH protocol and returns the output
// args[0] = SSH username
// args[1] = SSH password
// args[2] = the SSH host:port
// args[3] = the program to execute
// args[4] = program arguments (optional)
func SSH(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.SSH(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Token is used to interact with Windows Access Tokens on the agent
// args[0] = the token method (e.g., make|privs|rev2self|steal|whoami)
// args[1:] = method arguments
func Token(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Token(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Touch matches the destination file's timestamps with source file
// args[0] = the source file
// args[1] = the destination file
func Touch(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Touch(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// UnlinkAgent instructs the parent Agent to close, or unlink, the connection with the child Agent
// args[0] = the child Agent ID to unlink
func UnlinkAgent(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.UnlinkAgent(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Upload transfers a file from the Merlin Server to the Agent
// args[0] = the source file as a Base64 encoded string
// args[1] = the destination file path
func Upload(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Upload(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Uptime retrieves the target host's uptime. Windows only
func Uptime(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Uptime(context.Background(), &pb.ID{Id: id.String()}))
}
