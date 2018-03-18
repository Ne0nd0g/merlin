// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2018  Russel Van Tuyl

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

package cli

import (
	// Standard
	"log"
	"io"
	"strings"
	"os"
	"os/exec"
	"fmt"
	"time"
	"path"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"
	"github.com/fatih/color"
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/modules"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/banner"
)

// Global Variables
var serverLog *os.File
var shellModule modules.Module
var shellAgent uuid.UUID
var prompt *readline.Instance
var shellCompleter *readline.PrefixCompleter
var shellMenuContext = "main"

// Shell is the exported function to start the command line interface
func Shell() {

	shellCompleter = getCompleter("main")

	p, err := readline.NewEx(&readline.Config{
		Prompt:              "\033[31mMerlin»\033[0m ",
		HistoryFile:         "/tmp/readline.tmp",
		AutoComplete:        shellCompleter,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})

	if err != nil {
		color.Red("[!]There was an error with the provided input")
		color.Red(err.Error())
	}
	prompt = p
	defer prompt.Close()

	log.SetOutput(prompt.Stderr())

	for {
		line, err := prompt.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		cmd := strings.Fields(line)

		if len(cmd) > 0 {
			switch shellMenuContext {
			case "main":
				switch cmd[0] {
				case "agent":
					if len(cmd) > 1 {
						menuAgent(cmd[1:])
					}
				case "banner":
					color.Blue(banner.Banner1)
					color.Blue("\t\t   Version: %s", merlin.Version)
				case "help":
					menuHelpMain()
				case "?":
					menuHelpMain()
				case "exit":
					exit()
				case "interact":
					if len(cmd) > 1 {
						i := []string{"interact"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
				case "quit":
					exit()
				case "sessions":
					menuAgent([]string{"list"})
				case "use":
					menuUse(cmd[1:])
				case "version":
					color.Blue(fmt.Sprintf("Merlin version: %s", merlin.Version))
				case "":
				default:
					message("info", "Executing system command...")
					if len(cmd) > 1 {
						executeCommand(cmd[0], cmd[1:])
					} else {
						var x []string
						executeCommand(cmd[0], x)
					}
				}
			case "module":
				switch cmd[0] {
				case "show":
					if len(cmd) > 1{
						switch cmd[1] {
						case "info":
							shellModule.ShowInfo()
						case "options":
							shellModule.ShowOptions()
						}
					}
				case "set":
					if len(cmd) > 2 {
						if cmd[1] == "agent"{
							s, err := shellModule.SetAgent(cmd[2])
							if err != nil {message("warn", err.Error())} else {message("success", s)}
						} else {
							s, err := shellModule.SetOption(cmd[1], cmd[2])
							if err != nil {message("warn", err.Error())} else {message("success", s)}
						}
					}
				case "reload":
					menuSetModule(strings.TrimSuffix(strings.Join(shellModule.Path, "/"), ".json"))
				case "run":
					r, err := shellModule.Run()
					if err != nil {
						message("warn", err.Error())
					} else {
						err := agents.AddChannel(shellModule.Agent, "cmd", r)
						if err != nil {message("warn", err.Error())}
					}
				case "back":
					menuSetMain()
				case "main":
					menuSetMain()
				case "exit":
					exit()
				case "quit":
					exit()
				case "help":
					menuHelpModule()
				case "?":
					menuHelpModule()
				default:
					message("info", "Executing system command...")
					if len(cmd) > 1 {
						executeCommand(cmd[0], cmd[1:])
					} else {
						var x []string
						executeCommand(cmd[0], x)
					}
				}
			case "agent":
				switch cmd[0] {
				case "back":
					menuSetMain()
				case "cmd":
					if len(cmd) >1{
						err := agents.AddChannel(shellAgent, "cmd", cmd[1:])
						if err != nil {message("warn", err.Error())}
					}
				case "download":
					if len(cmd) >1{
						err := agents.AddChannel(shellAgent, "download", cmd[1:])
						if err != nil {message("warn", err.Error())}
					}
				case "exit":
					exit()
				case "help":
					menuHelpAgent()
				case "?":
					menuHelpAgent()
				case "info":
					agents.ShowInfo(shellAgent)
				case "kill":
					if len(cmd) >0{
						err := agents.AddChannel(shellAgent, "kill", cmd[0:]);menuSetMain()
						if err != nil {message("warn", err.Error())}
					}
				case "main":
					menuSetMain()
				case "quit":
					exit()
				case "set":
					if len(cmd) >1{
						switch cmd[1]{
						case "maxretry":
							if len(cmd) >2{
								err := agents.AddChannel(shellAgent, "AgentControl", cmd[1:])
								if err != nil {message("warn", err.Error())}
							}
						case "padding":
							if len(cmd) >2{
								err := agents.AddChannel(shellAgent, "AgentControl", cmd[1:])
								if err != nil {message("warn", err.Error())}
							}
						case "sleep":
							if len(cmd) >2{
								err := agents.AddChannel(shellAgent, "AgentControl", cmd[1:])
								if err != nil {message("warn", err.Error())}
							}
						case "skew":
							if len(cmd) >2{
								err := agents.AddChannel(shellAgent, "AgentControl", cmd[1:])
								if err != nil {message("warn", err.Error())}
							}
						}
					}
				case "upload":
					if len(cmd) >1{
						agents.AddChannel(shellAgent, "upload", cmd[1:])
						if err != nil {message("warn", err.Error())}
					}
				default:
					message("info", "Executing system command...")
					if len(cmd) > 1 {
						executeCommand(cmd[0], cmd[1:])
					} else {
						var x []string
						executeCommand(cmd[0], x)
					}
				}
			}
		}

	}
}

func menuUse(cmd []string) {
	if len(cmd) > 0 {
		switch cmd[0] {
		case "module":
			if len(cmd) > 1 {
				menuSetModule(cmd[1])
			} else {
				message("warn", "Invalid module")
			}
		case "":
		default:
			color.Yellow("[-]Invalid 'use' command")
		}
	} else {
		color.Yellow("[-]Invalid 'use' command")
	}
}

func menuAgent(cmd []string){
	switch cmd[0] {
	case "list":
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Agent GUID", "Platform", "User", "Host", "Transport"})
		table.SetAlignment(tablewriter.ALIGN_CENTER)
		for k, v := range agents.Agents {
			table.Append([]string{k.String(), v.Platform + "/" + v.Architecture, v.UserName,
				v.HostName, "HTTP/2"})
		}
		fmt.Println()
		table.Render()
		fmt.Println()
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				message("warn", fmt.Sprintf("There was an error interacting with agent %s", cmd[1]))
			} else {
				menuSetAgent(i)
			}
		}
	}
}

func menuSetAgent(agentID uuid.UUID) {
	for k := range agents.Agents{
		if agentID == agents.Agents[k].ID {
			shellAgent = agentID
			prompt.Config.AutoComplete = getCompleter("agent")
			prompt.SetPrompt("\033[31mMerlin[\033[32magent\033[31m][\033[33m" + shellAgent.String() + "\033[31m]»\033[0m ")
			shellMenuContext = "agent"
		}
	}
}

func menuSetModule(cmd string) {
	if len(cmd) > 0 {
		var mPath = path.Join(core.CurrentDir, "data", "modules", cmd + ".json")
		s, errModule := modules.Create(mPath)
		if errModule != nil {
			message("warn", errModule.Error())
		} else {
			shellModule = s
			prompt.Config.AutoComplete = getCompleter("module")
			prompt.SetPrompt("\033[31mMerlin[\033[32mmodule\033[31m][\033[33m" + shellModule.Name + "\033[31m]»\033[0m ")
			shellMenuContext = "module"
		}
	}
}

func menuSetMain(){
	prompt.Config.AutoComplete = getCompleter("main")
	prompt.SetPrompt("\033[31mMerlin»\033[0m ")
	shellMenuContext = "main"
}

func getCompleter(completer string) *readline.PrefixCompleter {

	// Main Menu Completer
	var main = readline.NewPrefixCompleter(
		readline.PcItem("agent",
			readline.PcItem("list"),
			readline.PcItem("interact",
				readline.PcItemDynamic(agents.GetAgentList()),
			),
		),
		readline.PcItem("banner"),
		readline.PcItem("help"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agents.GetAgentList()),
		),
		readline.PcItem("sessions"),
		readline.PcItem("use",
			readline.PcItem("module",
				readline.PcItemDynamic(modules.GetModuleList()),
			),
		),
		readline.PcItem("version"),
	)


	// Module Menu
	var module = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("help"),
		readline.PcItem("main"),
		readline.PcItem("reload"),
		readline.PcItem("run"),
		readline.PcItem("show",
			readline.PcItem("options"),
			readline.PcItem("info"),
		),
		readline.PcItem("set",
			readline.PcItem("agent",
				readline.PcItem("all"),
				readline.PcItemDynamic(agents.GetAgentList()),
			),
			readline.PcItemDynamic(shellModule.GetOptionsList()),
		),
	)

	// Agent Menu
	var agent = readline.NewPrefixCompleter(
		readline.PcItem("cmd"),
		readline.PcItem("back"),
		readline.PcItem("download"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("kill"),
		readline.PcItem("main"),
		readline.PcItem("set",
			readline.PcItem("maxretry"),
			readline.PcItem("padding"),
			readline.PcItem("skew"),
			readline.PcItem("sleep"),
		),
		readline.PcItem("upload"),
	)

	switch completer {
	case "main":
		return main
	case "module":
		return module
	case "agent":
		return agent
	default:
		return main
	}
	return main
}

func menuHelpMain() {
	color.Yellow("Merlin C2 Server (version %s)", merlin.Version)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"agent", "Interact with agents or list agents", "interact, list"},
		{"banner", "Print the Merlin banner", ""},
		{"exit", "Exit and close the Merlin server", ""},
		{"interact", "Interact with an agent. Alias for Empire users", ""},
		{"quit", "Exit and close the Merlin server", ""},
		{"sessions", "List all agents session information. Alias for MSF users", ""},
		{"use", "Use a function of Merlin", "module"},
		{"version", "Print the Merlin server version", ""},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// The help menu while in the modules menu
func menuHelpModule(){
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	// table.SetCaption(true, "Module Menu Help") // TODO Need to upgrade library first
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"main", "Return to the main menu", ""},
		{"reload", "Reloads the module to a fresh clean state"},
		{"run","Run or execute the module", ""},
		{"set", "Set the value for one of the module's options", "<option name> <option value>"},
		{"show", "Show information about a module or its options", "info, options"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// The help menu while in the agent menu
func menuHelpAgent() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	// table.SetCaption(true, "Agent Menu Help") // TODO Need to upgrade library first
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"cmd", "Execute a command on the agent", "cmd ping -c 3 8.8.8.8"},
		{"back", "Return to the main menu", ""},
		{"download","Download a file from the agent", "download <remote_file>"},
		{"info", "Display all information about the agent", ""},
		{"kill", "Instruct the agent to die or quit", ""},
		{"main", "Return to the main menu", ""},
		{"set", "Set the value for one of the agent's options", "maxretry, padding, skew, sleep"},
		{"upload", "Upload a file to the agent", "upload <local_file> <remote_file>"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

// Message is used to print a message to the command line
func message (level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}

func exit(){
	color.Red("[!]Quitting")
	serverLog.WriteString(fmt.Sprintf("[%s]Shutting down Merlin Server due to user input", time.Now()))
	os.Exit(0)
}

func executeCommand(name string, arg []string) {
	var cmd *exec.Cmd

	cmd = exec.Command(name, arg...)

	out, err := cmd.CombinedOutput()

	if err != nil {
		message("warn", err.Error())
	} else {
		message("success", fmt.Sprintf("%s", out))
	}
}

// TODO add command "agents" to list all connected agents
// TODO add command "info" for agent and module menu in addition to "show info"
// TODO create a function to display an agent's status; Green = active, Yellow = missed checkin, Red = missed max retry