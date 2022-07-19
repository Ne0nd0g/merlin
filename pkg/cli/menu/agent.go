// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package menu

import (
	// Standard
	"fmt"
	"os"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Merlin
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
)

// agent is used to track the current agent that the CLI is interacting with
var agent uuid.UUID

// platform tracks the current agent's platform or operating system used to provide specific menus
var platform string

// handlerAgent contains the logic to handle the "agent" menu commands
func handlerAgent(cmd []string) {
	// TODO create a structure for every command that has a Name,Function,Help
	if len(cmd) <= 0 {
		return
	}
	switch cmd[0] {
	case "back":
		Set(MAIN)
	case "cd":
		core.MessageChannel <- agentAPI.CD(agent, cmd)
	case "clear", "c":
		core.MessageChannel <- agentAPI.ClearJobs(agent)
	case "download":
		core.MessageChannel <- agentAPI.Download(agent, cmd)
	case "env":
		core.MessageChannel <- agentAPI.ENV(agent, cmd)
	case "execute-assembly", "assembly":
		go func() { core.MessageChannel <- agentAPI.ExecuteAssembly(agent, cmd) }()
	case "execute-pe", "pe":
		go func() { core.MessageChannel <- agentAPI.ExecutePE(agent, cmd) }()
	case "execute-shellcode", "shinject":
		core.MessageChannel <- agentAPI.ExecuteShellcode(agent, cmd)
	case "exit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.MessageChannel <- agentAPI.Exit(agent, cmd)
				Set(MAIN)
			}
		} else {
			if core.Confirm("Are you sure that you want to exit the agent?") {
				core.MessageChannel <- agentAPI.Exit(agent, cmd)
				Set(MAIN)
			}
		}
	case "group":
		if len(cmd) != 3 {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Invalid arguments: 'group <add | remove> <groupname>",
				Time:    time.Now().UTC(),
				Error:   true,
			}
		} else if cmd[1] == "add" {
			core.MessageChannel <- agentAPI.GroupAdd(agent, cmd[2])
		} else if cmd[1] == "remove" {
			core.MessageChannel <- agentAPI.GroupRemove(agent, cmd[2])
		} else {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Invalid arguments: group <add | remove> <groupname>",
				Time:    time.Now().UTC(),
				Error:   true,
			}
		}
	case "?", "help":
		helpAgent()
	case "ifconfig", "ipconfig":
		core.MessageChannel <- agentAPI.IFConfig(agent)
	case "info":
		rows, message := agentAPI.GetAgentInfo(agent)
		if message.Error {
			core.MessageChannel <- message
		} else {
			core.DisplayTable([]string{}, rows)
		}
	case "interact":
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "invoke-assembly":
		core.MessageChannel <- agentAPI.InvokeAssembly(agent, cmd)
	case "ja3":
		core.MessageChannel <- agentAPI.JA3(agent, cmd)
	case "jobs":
		jobs, message := agentAPI.GetJobsForAgent(agent)
		if message.Message != "" {
			core.MessageChannel <- message
		}
		displayJobTable(jobs)
	case "kill":
		core.MessageChannel <- agentAPI.KillProcess(agent, cmd)
	case "killdate":
		core.MessageChannel <- agentAPI.KillDate(agent, cmd)
	case "list-assemblies":
		core.MessageChannel <- agentAPI.ListAssemblies(agent)
	case "load-assembly":
		core.MessageChannel <- agentAPI.LoadAssembly(agent, cmd)
	case "load-clr":
		core.MessageChannel <- agentAPI.LoadCLR(agent, cmd)
	case "ls":
		core.MessageChannel <- agentAPI.LS(agent, cmd)
	case "main":
		Set(MAIN)
	case "make_token":
		c := []string{"token", "make"}
		if len(cmd) > 1 {
			c = append(c, cmd[1:]...)
		}
		core.MessageChannel <- agentAPI.Token(agent, c)
	case "maxretry":
		core.MessageChannel <- agentAPI.MaxRetry(agent, cmd)
	case "memory":
		core.MessageChannel <- agentAPI.Memory(agent, cmd)
	case "memfd":
		core.MessageChannel <- agentAPI.MEMFD(agent, cmd)
	case "netstat":
		core.MessageChannel <- agentAPI.Netstat(agent, cmd)
	case "note":
		if len(cmd) > 1 {
			core.MessageChannel <- agentAPI.Note(agent, cmd[1:])
		} else {
			core.MessageChannel <- agentAPI.Note(agent, []string{})
		}
	case "nslookup":
		core.MessageChannel <- agentAPI.NSLOOKUP(agent, cmd)
	case "padding":
		core.MessageChannel <- agentAPI.Padding(agent, cmd)
	case "pipes":
		core.MessageChannel <- agentAPI.Pipes(agent)
	case "printenv":
		core.MessageChannel <- agentAPI.ENV(agent, []string{"env", "showall"})
	case "ps":
		core.MessageChannel <- agentAPI.PS(agent)
	case "pwd":
		core.MessageChannel <- agentAPI.PWD(agent, cmd)
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.Exit()
			}
		}
		if core.Confirm("Are you sure you want to quit Merlin?") {
			core.Exit()
		}
	case "rev2self":
		core.MessageChannel <- agentAPI.Token(agent, []string{"token", "rev2self"})
	case "rm":
		core.MessageChannel <- agentAPI.RM(agent, cmd)
	case "run", "shell", "exec":
		core.MessageChannel <- agentAPI.CMD(agent, cmd)
	case "runas":
		core.MessageChannel <- agentAPI.RunAs(agent, cmd)
	case "sdelete":
		core.MessageChannel <- agentAPI.SecureDelete(agent, cmd)
	case "sessions":
		header, rows := agentAPI.GetAgentsRows()
		core.DisplayTable(header, rows)
	case "sharpgen":
		go func() { core.MessageChannel <- agentAPI.SharpGen(agent, cmd) }()
	case "skew":
		core.MessageChannel <- agentAPI.Skew(agent, cmd)
	case "sleep":
		core.MessageChannel <- agentAPI.Sleep(agent, cmd)
	case "socks":
		core.MessageChannel <- agentAPI.Socks(agent, cmd)
	case "ssh":
		core.MessageChannel <- agentAPI.SSH(agent, cmd)
	case "status":
		status, message := agentAPI.GetAgentStatus(agent)
		if message.Error {
			core.MessageChannel <- message
		}
		if status == "Active" {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.GreenString("%s agent is active\n", agent),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		} else if status == "Delayed" {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.YellowString("%s agent is delayed\n", agent),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		} else if status == "Dead" {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.RedString("%s agent is dead\n", agent),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		} else {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.BlueString("%s agent is %s\n", agent, status),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	case "steal_token":
		c := []string{"token", "steal"}
		if len(cmd) > 1 {
			c = append(c, cmd[1:]...)
		}
		core.MessageChannel <- agentAPI.Token(agent, c)
	case "token":
		core.MessageChannel <- agentAPI.Token(agent, cmd)
	case "touch", "timestomp":
		core.MessageChannel <- agentAPI.Touch(agent, cmd)
	case "upload":
		core.MessageChannel <- agentAPI.Upload(agent, cmd)
	case "uptime":
		core.MessageChannel <- agentAPI.Uptime(agent)
	default:
		if cmd[0][0:1] == "!" {
			if len(cmd) > 1 {
				core.ExecuteCommand(cmd[0][1:], cmd[1:])
			} else {
				core.ExecuteCommand(cmd[0][1:], nil)
			}
		} else {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("unrecognized command: %s", cmd[0]),
				Time:    time.Now().UTC(),
				Error:   true,
			}
		}
	}
}

// completerAgent returns a list of tab completable commands available in the "agent" menu based on the Agent's platform
func completerAgent() *readline.PrefixCompleter {
	// core commands are available to every agent and typically use native Go code
	base := []readline.PrefixCompleterInterface{
		readline.PcItem("back"),
		readline.PcItem("cd"),
		readline.PcItem("clear"),
		readline.PcItem("download"),
		readline.PcItem("env",
			readline.PcItem("get"),
			readline.PcItem("set"),
			readline.PcItem("showall"),
			readline.PcItem("unset"),
		),
		readline.PcItem("exit"),
		readline.PcItem("group",
			readline.PcItem("add",
				readline.PcItemDynamic(completerGroup()),
			),
			readline.PcItem("remove",
				readline.PcItemDynamic(completerGroup()),
			),
		),
		readline.PcItem("help"),
		readline.PcItem("ifconfig"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("ja3"),
		readline.PcItem("jobs"),
		readline.PcItem("kill"),
		readline.PcItem("killdate"),
		readline.PcItem("ls"),
		readline.PcItem("main"),
		readline.PcItem("maxretry"),
		readline.PcItem("note"),
		readline.PcItem("padding"),
		readline.PcItem("printenv"),
		readline.PcItem("pwd"),
		readline.PcItem("quit"),
		readline.PcItem("rm"),
		readline.PcItem("run"),
		readline.PcItem("sdelete"),
		readline.PcItem("sessions"),
		readline.PcItem("shell"),
		readline.PcItem("skew"),
		readline.PcItem("sleep"),
		readline.PcItem("socks",
			readline.PcItem("list"),
			readline.PcItem("start"),
			readline.PcItem("stop"),
		),
		readline.PcItem("ssh"),
		readline.PcItem("status"),
		readline.PcItem("touch"),
		readline.PcItem("upload"),
	}

	// Commands only available to Windows agents
	windows := []readline.PrefixCompleterInterface{
		readline.PcItem("execute-assembly"),
		readline.PcItem("execute-pe"),
		readline.PcItem("execute-shellcode",
			readline.PcItem("self"),
			readline.PcItem("remote"),
			readline.PcItem("RtlCreateUserThread"),
		),
		readline.PcItem("invoke-assembly"),
		readline.PcItem("list-assemblies"),
		readline.PcItem("load-assembly"),
		readline.PcItem("memory",
			readline.PcItem("read"),
			readline.PcItem("patch"),
			readline.PcItem("write"),
		),
		readline.PcItem("netstat"),
		readline.PcItem("pipes"),
		readline.PcItem("ps"),
		readline.PcItem("runas"),
		readline.PcItem("sharpgen"),
		readline.PcItem("token",
			readline.PcItem("make"),
			readline.PcItem("privs"),
			readline.PcItem("rev2self"),
			readline.PcItem("steal"),
			readline.PcItem("whoami"),
		),
		readline.PcItem("uptime"),
	}

	// Commands only available to Linux agents
	linux := []readline.PrefixCompleterInterface{
		readline.PcItem("memfd"),
	}

	// TODO Sort the combined slice
	if strings.HasPrefix(strings.ToLower(platform), "linux/") {
		return readline.NewPrefixCompleter(append(base, linux...)...)
	} else if strings.HasPrefix(strings.ToLower(platform), "windows/") {
		return readline.NewPrefixCompleter(append(base, windows...)...)
	} else {
		return readline.NewPrefixCompleter(base...)
	}
}

// helpAgent displays the help information for the "agent" menu
func helpAgent() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Agent Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	// Commands available to all agents
	base := [][]string{
		{"cd", "Change directories", "cd ../../ OR cd c:\\\\Users"},
		{"clear", "Clear any UNSENT jobs from the queue", ""},
		{"back", "Return to the main menu", ""},
		{"download", "Download a file from the agent", "download <remote_file>"},
		{"env", "View and modify environment variables", "env <get | set | unset | showall> [variable] [value]"},
		{"exit", "Instruct the agent to exit and quit running", ""},
		{"ifconfig", "Displays host network adapter information", ""},
		{"group", "Add or remove the current agent to/from a group", "group <add|remove> <group name>"},
		{"interact", "Interact with an agent", ""},
		{"info", "Display all information about the agent", ""},
		{"ja3", "Set the agent's JA3 client signature", "ja3 <ja3 signature string>"},
		{"jobs", "Display all active jobs for the agent", ""},
		{"kill", "Kill a running process by its numerical identifier (pid)", "kill <pid>"},
		{"killdate", "Set the epoch date/time the agent will quit running", "killdate <epoch date>"},
		{"ls", "List directory contents", "ls /etc OR ls C:\\\\Users OR ls C:/Users"},
		{"main", "Return to the main menu", ""},
		{"maxretry", "Set the maximum amount of times the agent can fail to check in before it dies", "maxretery <number>"},
		{"note", "Add a server-side note to the agent", ""},
		{"nslookup", "DNS query on host or ip", "nslookup 8.8.8.8"},
		{"padding", "Set the maximum amount of random data appended to every message", "padding <number>"},
		{"printenv", "Print all environment variables. Alias for \"env showall\"", "printenv"},
		{"pwd", "Display the current working directory", "pwd"},
		{"quit", "Exit and close the Merlin server", "-y"},
		{"rm", "Remove, or delete, a file", "<file path>"},
		{"run", "Execute a program directly, without using a shell", "run ping -c 3 8.8.8.8"},
		{"sessions", "Display a table of information about all checked-in agent sessions", ""},
		{"sdelete", "Securely delete a file", "sdelete <file path>"},
		{"shell", "Execute a command on the agent using the host's default shell", "shell ping -c 3 8.8.8.8"},
		{"skew", "Set the amount of skew, or jitter, that an agent will use to checkin", "skew <number>"},
		{"sleep", "Set the agent's sleep interval using Go time format", "sleep 30s"},
		{"socks", "Start a SOCKS5 listener", "[list, start, stop] <interface:port> <agentID>"},
		{"ssh", "Execute command on remote host over SSH (non-interactive", "ssh <user> <pass> <host:port> <program> [<args>]"},
		{"status", "Print the current status of the agent", ""},
		{"touch", "Match destination file's timestamps with source file (alias timestomp)", "touch <source> <destination>"},
		{"upload", "Upload a file to the agent", "upload <local_file> <remote_file>"},
		{"!", "Execute a command on the host operating system", "!<command> <args>"},
	}

	windows := [][]string{
		{"execute-assembly", "Execute a .NET 4.0 assembly", "execute-assembly <assembly path> [<assembly args> <spawnto path> <spawnto args>]"},
		{"execute-pe", "Execute a Windows PE (EXE)", "execute-pe <pe path> [<pe args> <spawnto path> <spawnto args>]"},
		{"execute-shellcode", "Execute shellcode", "self, remote <pid>, RtlCreateUserThread <pid>"},
		{"invoke-assembly", "Invoke, or execute, a .NET assembly that was previously loaded into the agent's process", "<assembly name> <assembly args>"},
		{"load-assembly", "Load a .NET assembly into the agent's process", "<assembly path> [<assembly name>]"},
		{"list-assemblies", "List the .NET assemblies that are loaded into the agent's process", ""},
		{"memory", "Read or write memory for a provided module and function", "memory <patch,read,write> <module> <procedure> [length, bytes]"},
		{"netstat", "display network connections", "netstat [-p tcp|udp]"},
		{"pipes", "Enumerate all named pipes", ""},
		{"ps", "Get a list of running processes", ""},
		{"runas", "Run a program as another user", "<DOMAIN\\USER> <password> <program> [<args>]"},
		{"sharpgen", "Use SharpGen to compile and execute a .NET assembly", "sharpgen <code> [<spawnto path> <spawnto args>]"},
		{"token", "Interact with Windows access tokens", "<make | privs | rev2self | steal | whoami >"},
		{"uptime", "Retrieve the host's uptime"},
	}

	linux := [][]string{
		{"memfd", "Execute Linux file in memory", "<file path> [<arguments>]"},
	}

	table.AppendBulk(base)
	if strings.HasPrefix(strings.ToLower(platform), "windows/") {
		table.AppendBulk(windows)
	} else if strings.HasPrefix(strings.ToLower(platform), "linux/") {
		table.AppendBulk(linux)
	}

	fmt.Println()
	table.Render()
	fmt.Println()
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// interactAgent is used to issue commands to a specific agent
func interactAgent(id string) {
	agentID, err := uuid.FromString(id)
	if err != nil {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error interacting with agent %s", id),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	} else {
		// TODO Validate the agent exists
		agent = agentID
		setAgent(agentID)
		Set(AGENT)
	}
}

// removeAgent removes an agent from the sessions table and CLI
func removeAgent(id string) {
	i, errUUID := uuid.FromString(id)
	if errUUID != nil {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error interacting with agent %s", id),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	} else {
		core.MessageChannel <- agentAPI.Remove(i)
	}
}

// setAgent sets the current agent the CLI is interacting with based on the agent's ID
func setAgent(agentID uuid.UUID) {
	agentList := agentAPI.GetAgents()
	for _, id := range agentList {
		if agentID == id {
			agent = agentID
			agentInfo, m := agentAPI.GetAgentInfo(agent)
			if m.Error {
				core.MessageChannel <- m
				return
			}

			for i := range agentInfo {
				if strings.ToLower(agentInfo[i][0]) == "platform" {
					platform = agentInfo[i][1]
				}
			}
			// Return empty if unable to determine the platform
			if platform == "" {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "Unable to determine the agent's platform. Try again after next checkin...",
					Time:    time.Now().UTC(),
					Error:   true,
				}
				return
			}
		}
	}
}

// agentListCompleter returns a list of agents that exist and is used for command line tab completion
func agentListCompleter() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		agentList := agentAPI.GetAgents()
		for _, id := range agentList {
			a = append(a, id.String())
		}
		return a
	}
}

// displayJobTable displays a table of agent jobs along with their status
func displayJobTable(rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"ID", "Command", "Status", "Created", "Sent"})

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}
