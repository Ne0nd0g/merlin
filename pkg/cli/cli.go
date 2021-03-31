// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
	"github.com/olekukonko/tablewriter"
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/modules"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// Global Variables
var shellModule modules.Module
var shellAgent uuid.UUID
var shellListener listener
var shellListenerOptions map[string]string
var prompt *readline.Instance
var shellCompleter *readline.PrefixCompleter
var shellMenuContext = "main"

// MessageChannel is used to input user messages that are eventually written to STDOUT on the CLI application
var MessageChannel = make(chan messages.UserMessage)
var clientID = uuid.NewV4()

// Shell is the exported function to start the command line interface
func Shell() {

	shellCompleter = getCompleter("main")

	printUserMessage()
	registerMessageChannel()
	getUserMessages()

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
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error with the provided input: %s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
	prompt = p

	defer func() {
		err := prompt.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

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
			exit()
		}

		line = strings.TrimSpace(line)
		//cmd := strings.Fields(line)
		cmd, err := shellwords.Parse(line)
		if err != nil {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("error parsing command line arguments:\r\n%s", err),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}

		if len(cmd) > 0 {
			switch shellMenuContext {
			case "listener":
				menuListener(cmd)
			case "listenersmain":
				menuListeners(cmd)
			case "listenersetup":
				menuListenerSetup(cmd)
			case "main":
				switch cmd[0] {
				case "agent":
					if len(cmd) > 1 {
						menuAgent(cmd[1:])
					}
				case "banner":
					m := "\n"
					m += color.BlueString(banner.MerlinBanner1)
					m += color.BlueString("\r\n\t\t   Version: %s", merlin.Version)
					m += color.BlueString("\r\n\t\t   Build: %s\n", merlin.Build)
					MessageChannel <- messages.UserMessage{
						Level:   messages.Plain,
						Message: m,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				case "help":
					menuHelpMain()
				case "?":
					menuHelpMain()
				case "exit", "quit":
					if len(cmd) > 1 {
						if strings.ToLower(cmd[1]) == "-y" {
							exit()
						}
					}
					if confirm("Are you sure you want to exit?") {
						exit()
					}
				case "interact":
					if len(cmd) > 1 {
						i := []string{"interact"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
				case "listeners":
					shellMenuContext = "listenersmain"
					prompt.Config.AutoComplete = getCompleter("listenersmain")
					prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
				case "remove":
					if len(cmd) > 1 {
						i := []string{"remove"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
				case "sessions":
					menuAgent([]string{"list"})
				case "set":
					if len(cmd) > 2 {
						switch cmd[1] {
						case "verbose":
							if strings.ToLower(cmd[2]) == "true" {
								core.Verbose = true
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Verbose output enabled",
									Time:    time.Now(),
									Error:   false,
								}
							} else if strings.ToLower(cmd[2]) == "false" {
								core.Verbose = false
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Verbose output disabled",
									Time:    time.Now(),
									Error:   false,
								}
							}
						case "debug":
							if strings.ToLower(cmd[2]) == "true" {
								core.Debug = true
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Debug output enabled",
									Time:    time.Now().UTC(),
									Error:   false,
								}
							} else if strings.ToLower(cmd[2]) == "false" {
								core.Debug = false
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Debug output disabled",
									Time:    time.Now().UTC(),
									Error:   false,
								}
							}
						}
					}
				case "use":
					menuUse(cmd[1:])
				case "version":
					MessageChannel <- messages.UserMessage{
						Level:   messages.Plain,
						Message: color.BlueString("Merlin version: %s\n", merlin.Version),
						Time:    time.Now().UTC(),
						Error:   false,
					}
				case "":
				default:
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
					if len(cmd) > 1 {
						switch cmd[1] {
						case "info":
							shellModule.ShowInfo()
						case "options":
							shellModule.ShowOptions()
						}
					}
				case "info":
					shellModule.ShowInfo()
				case "set":
					if len(cmd) > 2 {
						if cmd[1] == "Agent" {
							s, err := shellModule.SetAgent(cmd[2])
							if err != nil {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Warn,
									Message: err.Error(),
									Time:    time.Now().UTC(),
									Error:   true,
								}
							} else {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: s,
									Time:    time.Now().UTC(),
									Error:   false,
								}
							}
						} else {
							s, err := shellModule.SetOption(cmd[1], cmd[2:])
							if err != nil {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Warn,
									Message: err.Error(),
									Time:    time.Now().UTC(),
									Error:   true,
								}
							} else {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: s,
									Time:    time.Now().UTC(),
									Error:   false,
								}
							}
						}
					}
				case "reload":
					menuSetModule(strings.TrimSuffix(strings.Join(shellModule.Path, "/"), ".json"))
				case "run":
					modMessages := moduleAPI.RunModule(shellModule)
					for _, message := range modMessages {
						MessageChannel <- message
					}
				case "back", "main":
					menuSetMain()
				case "exit", "quit":
					if len(cmd) > 1 {
						if strings.ToLower(cmd[1]) == "-y" {
							exit()
						}
					}
					if confirm("Are you sure you want to exit?") {
						exit()
					}
				case "unset":
					if len(cmd) >= 2 {
						s, err := shellModule.SetOption(cmd[1], nil)
						if err != nil {
							MessageChannel <- messages.UserMessage{
								Level:   messages.Warn,
								Message: err.Error(),
								Time:    time.Now().UTC(),
								Error:   true,
							}
						} else {
							MessageChannel <- messages.UserMessage{
								Level:   messages.Success,
								Message: s,
								Time:    time.Now().UTC(),
								Error:   false,
							}
						}
					}
				case "?", "help":
					menuHelpModule()
				default:
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
				case "cd":
					MessageChannel <- agentAPI.CD(shellAgent, cmd)
				case "clear":
					MessageChannel <- agentAPI.ClearJobs(shellAgent)
				case "download":
					MessageChannel <- agentAPI.Download(shellAgent, cmd)
				case "execute-assembly":
					go func() { MessageChannel <- agentAPI.ExecuteAssembly(shellAgent, cmd) }()
				case "execute-pe":
					go func() { MessageChannel <- agentAPI.ExecutePE(shellAgent, cmd) }()
				case "execute-shellcode":
					MessageChannel <- agentAPI.ExecuteShellcode(shellAgent, cmd)
				case "exit", "quit":
					if len(cmd) > 1 {
						if strings.ToLower(cmd[1]) == "-y" {
							exit()
						}
					}
					if confirm("Are you sure you want to exit?") {
						exit()
					}
				case "?", "help":
					menuHelpAgent()
				case "info":
					rows, message := agentAPI.GetAgentInfo(shellAgent)
					if message.Error {
						MessageChannel <- message
					} else {
						displayTable([]string{}, rows)
					}
				case "invoke-assembly":
					MessageChannel <- agentAPI.InvokeAssembly(shellAgent, cmd)
				case "jobs":
					jobs, message := agentAPI.GetJobsForAgent(shellAgent)
					if message.Message != "" {
						MessageChannel <- message
					}
					displayJobTable(jobs)
				case "memfd":
					MessageChannel <- agentAPI.MEMFD(shellAgent, cmd)
				case "nslookup":
					MessageChannel <- agentAPI.NSLOOKUP(shellAgent, cmd)
				case "kill":
					menuSetMain()
					MessageChannel <- agentAPI.Kill(shellAgent, cmd)
				case "list-assemblies":
					MessageChannel <- agentAPI.ListAssemblies(shellAgent)
				case "load-assembly":
					MessageChannel <- agentAPI.LoadAssembly(shellAgent, cmd)
				case "load-clr":
					MessageChannel <- agentAPI.LoadCLR(shellAgent, cmd)
				case "ls":
					MessageChannel <- agentAPI.LS(shellAgent, cmd)
				case "main":
					menuSetMain()
				case "pwd":
					MessageChannel <- agentAPI.PWD(shellAgent, cmd)
				case "run", "shell":
					MessageChannel <- agentAPI.CMD(shellAgent, cmd)
				case "set":
					if len(cmd) > 1 {
						switch cmd[1] {
						case "ja3":
							MessageChannel <- agentAPI.SetJA3(shellAgent, cmd)
						case "killdate":
							MessageChannel <- agentAPI.SetKillDate(shellAgent, cmd)
						case "maxretry":
							MessageChannel <- agentAPI.SetMaxRetry(shellAgent, cmd)
						case "padding":
							MessageChannel <- agentAPI.SetPadding(shellAgent, cmd)
						case "sleep":
							MessageChannel <- agentAPI.SetSleep(shellAgent, cmd)
						case "skew":
							MessageChannel <- agentAPI.SetSkew(shellAgent, cmd)
						default:
							MessageChannel <- messages.UserMessage{
								Level:   messages.Warn,
								Message: fmt.Sprintf("invalid option to set: %s", cmd[1]),
								Time:    time.Time{},
								Error:   true,
							}
						}
					}
				case "sharpgen":
					go func() { MessageChannel <- agentAPI.SharpGen(shellAgent, cmd) }()
				case "status":
					status, message := agentAPI.GetAgentStatus(shellAgent)
					if message.Error {
						MessageChannel <- message
					}
					if status == "Active" {
						MessageChannel <- messages.UserMessage{
							Level:   messages.Plain,
							Message: color.GreenString("%s agent is active\n", shellAgent),
							Time:    time.Now().UTC(),
							Error:   false,
						}
					} else if status == "Delayed" {
						MessageChannel <- messages.UserMessage{
							Level:   messages.Plain,
							Message: color.YellowString("%s agent is delayed\n", shellAgent),
							Time:    time.Now().UTC(),
							Error:   false,
						}
					} else if status == "Dead" {
						MessageChannel <- messages.UserMessage{
							Level:   messages.Plain,
							Message: color.RedString("%s agent is dead\n", shellAgent),
							Time:    time.Now().UTC(),
							Error:   false,
						}
					} else {
						MessageChannel <- messages.UserMessage{
							Level:   messages.Plain,
							Message: color.BlueString("%s agent is %s\n", shellAgent, status),
							Time:    time.Now().UTC(),
							Error:   false,
						}
					}
				case "upload":
					MessageChannel <- agentAPI.Upload(shellAgent, cmd)
				default:
					if len(cmd) > 1 {
						executeCommand(cmd[0], cmd[1:])
					} else {
						executeCommand(cmd[0], []string{})
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
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "Invalid module",
					Time:    time.Now().UTC(),
					Error:   false,
				}
			}
		case "":
		default:
			MessageChannel <- messages.UserMessage{
				Level:   messages.Note,
				Message: "Invalid 'use' command",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	} else {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Note,
			Message: "Invalid 'use' command",
			Time:    time.Now().UTC(),
			Error:   false,
		}
	}
}

func menuAgent(cmd []string) {
	switch cmd[0] {
	case "list":
		header, rows := agentAPI.GetAgentsRows()
		displayTable(header, rows)
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				menuSetAgent(i)
			}
		}
	case "remove":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				MessageChannel <- agentAPI.Remove(i)
			}
		}
	}
}

func menuSetAgent(agentID uuid.UUID) {
	agentList := agentAPI.GetAgents()
	for _, id := range agentList {
		if agentID == id {
			shellAgent = agentID
			prompt.Config.AutoComplete = getCompleter("agent")
			prompt.SetPrompt("\033[31mMerlin[\033[32magent\033[31m][\033[33m" + shellAgent.String() + "\033[31m]»\033[0m ")
			shellMenuContext = "agent"
		}
	}
}

// menuListener handles all the logic for interacting with an instantiated listener
func menuListener(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "back":
		shellMenuContext = "listenersmain"
		prompt.Config.AutoComplete = getCompleter("listenersmain")
		prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
	case "delete":
		if confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", shellListener.name)) {
			um := listenerAPI.Remove(shellListener.name)
			if !um.Error {
				shellListener = listener{}
				shellListenerOptions = nil
				shellMenuContext = "listenersmain"
				prompt.Config.AutoComplete = getCompleter("listenersmain")
				prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
			} else {
				MessageChannel <- um
			}
		}
	case "exit", "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to exit?") {
			exit()
		}
	case "help":
		menuHelpListener()
	case "info", "show":
		um, options := listenerAPI.GetListenerConfiguredOptions(shellListener.id)
		if um.Error {
			MessageChannel <- um
			break
		}
		statusMessage := listenerAPI.GetListenerStatus(shellListener.id)
		if statusMessage.Error {
			MessageChannel <- statusMessage
			break
		}
		shellListener.status = listenerAPI.GetListenerStatus(shellListener.id).Message
		if options != nil {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Value"})
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(true)
			table.SetBorder(true)

			for k, v := range options {
				table.Append([]string{k, v})
			}
			table.Append([]string{"Status", shellListener.status})
			table.Render()
		}
	case "main":
		menuSetMain()
	case "restart":
		MessageChannel <- listenerAPI.Restart(shellListener.id)
		um, options := listenerAPI.GetListenerConfiguredOptions(shellListener.id)
		if um.Error {
			MessageChannel <- um
			break
		}
		prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + options["Name"] + "\033[31m]»\033[0m ")
	case "set":
		MessageChannel <- listenerAPI.SetOption(shellListener.id, cmd)
	case "start":
		MessageChannel <- listenerAPI.Start(shellListener.name)
	case "status":
		MessageChannel <- listenerAPI.GetListenerStatus(shellListener.id)
	case "stop":
		MessageChannel <- listenerAPI.Stop(shellListener.name)
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			executeCommand(cmd[0], x)
		}
	}
}

// menuListeners handles all the logic for the root Listeners menu
func menuListeners(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "exit", "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to exit?") {
			exit()
		}
	case "delete":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			um := listenerAPI.Exists(name)
			if um.Error {
				MessageChannel <- um
				return
			}
			if confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", name)) {
				removeMessage := listenerAPI.Remove(name)
				MessageChannel <- removeMessage
				if removeMessage.Error {
					return
				}
				shellListener = listener{}
				shellListenerOptions = nil
				shellMenuContext = "listenersmain"
				prompt.Config.AutoComplete = getCompleter("listenersmain")
				prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
			}
		}
	case "help":
		menuHelpListenersMain()
	case "info":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			um := listenerAPI.Exists(name)
			if um.Error {
				MessageChannel <- um
				return
			}
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				MessageChannel <- r
				return
			}
			if id == uuid.Nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "a nil Listener UUID was returned",
					Time:    time.Time{},
					Error:   true,
				}
			}
			oMessage, options := listenerAPI.GetListenerConfiguredOptions(id)
			if oMessage.Error {
				MessageChannel <- oMessage
				return
			}
			if options != nil {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Name", "Value"})
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetRowLine(true)
				table.SetBorder(true)

				for k, v := range options {
					table.Append([]string{k, v})
				}
				table.Render()
			}
		}
	case "interact":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				MessageChannel <- r
				return
			}
			if id == uuid.Nil {
				return
			}

			status := listenerAPI.GetListenerStatus(id).Message
			shellListener = listener{
				id:     id,
				name:   name,
				status: status,
			}
			shellMenuContext = "listener"
			prompt.Config.AutoComplete = getCompleter("listener")
			prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + name + "\033[31m]»\033[0m ")
		} else {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Note,
				Message: "you must select a listener to interact with",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	case "list":
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Name", "Interface", "Port", "Protocol", "Status", "Description"})
		table.SetAlignment(tablewriter.ALIGN_CENTER)
		listeners := listenerAPI.GetListeners()
		for _, v := range listeners {
			table.Append([]string{
				v.Name,
				v.Server.GetInterface(),
				fmt.Sprintf("%d", v.Server.GetPort()),
				servers.GetProtocol(v.Server.GetProtocol()),
				servers.GetStateString(v.Server.Status()),
				v.Description})
		}
		fmt.Println()
		table.Render()
		fmt.Println()
	case "main", "back":
		menuSetMain()
	case "start":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			MessageChannel <- listenerAPI.Start(name)
		}
	case "stop":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			MessageChannel <- listenerAPI.Stop(name)
		}
	case "use":
		if len(cmd) >= 2 {
			types := listenerAPI.GetListenerTypes()
			for _, v := range types {
				if strings.ToLower(cmd[1]) == v {
					shellListenerOptions = listenerAPI.GetListenerOptions(cmd[1])
					shellListenerOptions["Protocol"] = strings.ToLower(cmd[1])
					shellMenuContext = "listenersetup"
					prompt.Config.AutoComplete = getCompleter("listenersetup")
					prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + strings.ToLower(cmd[1]) + "\033[31m]»\033[0m ")
				}
			}
		}
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			executeCommand(cmd[0], x)
		}
	}
}

// menuListenerSetup handles all of the logic for setting up a Listener
func menuListenerSetup(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "back":
		shellMenuContext = "listenersmain"
		prompt.Config.AutoComplete = getCompleter("listenersmain")
		prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
	case "exit", "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to exit?") {
			exit()
		}
	case "help":
		menuHelpListenerSetup()
	case "info", "show":
		if shellListenerOptions != nil {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Value"})
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(true)
			table.SetBorder(true)

			for k, v := range shellListenerOptions {
				table.Append([]string{k, v})
			}
			table.Render()
		}
	case "main":
		menuSetMain()
	case "set":
		if len(cmd) >= 2 {
			for k := range shellListenerOptions {
				if cmd[1] == k {
					shellListenerOptions[k] = strings.Join(cmd[2:], " ")
					m := fmt.Sprintf("set %s to: %s", k, strings.Join(cmd[2:], " "))
					MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: m,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				}
			}
		}
	case "start", "run", "execute":
		um, id := listenerAPI.NewListener(shellListenerOptions)
		MessageChannel <- um
		if um.Error {
			return
		}
		if id == uuid.Nil {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "a nil Listener UUID was returned",
				Time:    time.Time{},
				Error:   true,
			}
			return
		}

		shellListener = listener{id: id, name: shellListenerOptions["Name"]}
		startMessage := listenerAPI.Start(shellListener.name)
		shellListener.status = listenerAPI.GetListenerStatus(id).Message
		MessageChannel <- startMessage
		um, options := listenerAPI.GetListenerConfiguredOptions(shellListener.id)
		if um.Error {
			MessageChannel <- um
			break
		}
		shellMenuContext = "listener"
		prompt.Config.AutoComplete = getCompleter("listener")
		prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + options["Name"] + "\033[31m]»\033[0m ")
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			executeCommand(cmd[0], x)
		}
	}
}

func menuSetModule(cmd string) {
	if len(cmd) > 0 {
		mPath := path.Join(core.CurrentDir, "data", "modules", cmd+".json")
		um, m := moduleAPI.GetModule(mPath)
		if um.Error {
			MessageChannel <- um
			return
		}
		if m.Name != "" {
			shellModule = m
			prompt.Config.AutoComplete = getCompleter("module")
			prompt.SetPrompt("\033[31mMerlin[\033[32mmodule\033[31m][\033[33m" + shellModule.Name + "\033[31m]»\033[0m ")
			shellMenuContext = "module"
		}
	}
}

func menuSetMain() {
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
				readline.PcItemDynamic(agentListCompleter()),
			),
		),
		readline.PcItem("banner"),
		readline.PcItem("help"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("listeners"),
		readline.PcItem("remove",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("sessions"),
		readline.PcItem("use",
			readline.PcItem("module",
				readline.PcItemDynamic(moduleAPI.GetModuleListCompleter()),
			),
		),
		readline.PcItem("version"),
	)

	// Module Menu
	var module = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("main"),
		readline.PcItem("reload"),
		readline.PcItem("run"),
		readline.PcItem("show",
			readline.PcItem("options"),
			readline.PcItem("info"),
		),
		readline.PcItem("set",
			readline.PcItem("Agent",
				readline.PcItem("all"),
				readline.PcItemDynamic(agentListCompleter()),
			),
			readline.PcItemDynamic(shellModule.GetOptionsList()),
		),
		readline.PcItem("unset",
			readline.PcItemDynamic(shellModule.GetOptionsList()),
		),
	)

	// Agent Menu
	var agent = readline.NewPrefixCompleter(
		readline.PcItem("cd"),
		readline.PcItem("clear"),
		readline.PcItem("cmd"),
		readline.PcItem("back"),
		readline.PcItem("download"),
		readline.PcItem("execute-assembly"),
		readline.PcItem("execute-pe"),
		readline.PcItem("execute-shellcode",
			readline.PcItem("self"),
			readline.PcItem("remote"),
			readline.PcItem("RtlCreateUserThread"),
		),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("invoke-assembly"),
		readline.PcItem("jobs"),
		readline.PcItem("kill"),
		readline.PcItem("list-assemblies"),
		readline.PcItem("load-assembly"),
		readline.PcItem("ls"),
		readline.PcItem("memfd"),
		readline.PcItem("pwd"),
		readline.PcItem("run"),
		readline.PcItem("main"),
		readline.PcItem("shell"),
		readline.PcItem("set",
			readline.PcItem("ja3"),
			readline.PcItem("killdate"),
			readline.PcItem("maxretry"),
			readline.PcItem("padding"),
			readline.PcItem("skew"),
			readline.PcItem("sleep"),
		),
		readline.PcItem("sharpgen"),
		readline.PcItem("status"),
		readline.PcItem("upload"),
	)

	// Listener Menu (a specific listener)
	var listener = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("delete"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("main"),
		readline.PcItem("remove"),
		readline.PcItem("restart"),
		readline.PcItem("set",
			readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(shellListenerOptions["Protocol"])),
		),
		readline.PcItem("show"),
		readline.PcItem("start"),
		readline.PcItem("status"),
		readline.PcItem("stop"),
	)

	// Listeners Main Menu (the root menu)
	var listenersmain = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("delete",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("help"),
		readline.PcItem("info",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("interact",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("list"),
		readline.PcItem("main"),
		readline.PcItem("start",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("stop",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("use",
			readline.PcItemDynamic(listenerAPI.GetListenerTypesCompleter()),
		),
	)

	// Listener Setup Menu
	var listenersetup = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("execute"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("main"),
		readline.PcItem("run"),
		readline.PcItem("set",
			readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(shellListenerOptions["Protocol"])),
		),
		readline.PcItem("show"),
		readline.PcItem("start"),
		readline.PcItem("stop"),
	)

	switch completer {
	case "agent":
		return agent
	case "listener":
		return listener
	case "listenersmain":
		return listenersmain
	case "listenersetup":
		return listenersetup
	case "main":
		return main
	case "module":
		return module
	default:
		return main
	}
}

func menuHelpMain() {
	MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: color.YellowString("Merlin C2 Server (version %s)\n", merlin.Version),
		Time:    time.Now().UTC(),
		Error:   false,
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Main Menu Help")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"agent", "Interact with agents or list agents", "interact, list"},
		{"banner", "Print the Merlin banner", ""},
		{"exit", "Exit and close the Merlin server", ""},
		{"listeners", "Move to the listeners menu", ""},
		{"interact", "Interact with an agent. Alias for Empire users", ""},
		{"quit", "Exit and close the Merlin server", ""},
		{"remove", "Remove or delete a DEAD agent from the server"},
		{"sessions", "List all agents session information. Alias for MSF users", ""},
		{"use", "Use a function of Merlin", "module"},
		{"version", "Print the Merlin server version", ""},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/main.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// The help menu while in the modules menu
func menuHelpModule() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Module Menu Help")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"info", "Show information about a module"},
		{"main", "Return to the main menu", ""},
		{"reload", "Reloads the module to a fresh clean state"},
		{"run", "Run or execute the module", ""},
		{"set", "Set the value for one of the module's options", "<option name> <option value>"},
		{"show", "Show information about a module or its options", "info, options"},
		{"unset", "Clear a module option to empty", "<option name>"},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/modules.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// The help menu while in the agent menu
func menuHelpAgent() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Agent Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"cd", "Change directories", "cd ../../ OR cd c:\\\\Users"},
		{"clear", "Clear any UNSENT jobs from the queue", ""},
		{"cmd", "Execute a command on the agent (DEPRECIATED)", "cmd ping -c 3 8.8.8.8"},
		{"back", "Return to the main menu", ""},
		{"download", "Download a file from the agent", "download <remote_file>"},
		{"execute-assembly", "Execute a .NET 4.0 assembly", "execute-assembly <assembly path> [<assembly args>, <spawnto path>, <spawnto args>]"},
		{"execute-pe", "Execute a Windows PE (EXE)", "execute-pe <pe path> [<pe args>, <spawnto path>, <spawnto args>]"},
		{"execute-shellcode", "Execute shellcode", "self, remote <pid>, RtlCreateUserThread <pid>"},
		{"info", "Display all information about the agent", ""},
		{"invoke-assembly", "Invoke, or execute, a .NET assembly that was previously loaded into the agent's process", "<assembly name>, <assembly args>"},
		{"jobs", "Display all active jobs for the agent", ""},
		{"kill", "Instruct the agent to die or quit", ""},
		{"load-assembly", "Load a .NET assembly into the agent's process", "<assembly path> [<assembly name>]"},
		{"list-assemblies", "List the .NET assemblies that are loaded into the agent's process", ""},
		{"ls", "List directory contents", "ls /etc OR ls C:\\\\Users OR ls C:/Users"},
		{"main", "Return to the main menu", ""},
		{"memfd", "Execute Linux file in memory", "<file path> [<arguments>]"},
		{"nslookup", "DNS query on host or ip", "nslookup 8.8.8.8"},
		{"pwd", "Display the current working directory", "pwd"},
		{"run", "Execute a program directly, without using a shell", "run ping -c 3 8.8.8.8"},
		{"set", "Set the value for one of the agent's options", "ja3, killdate, maxretry, padding, skew, sleep"},
		{"sharpgen", "Use SharpGen to compile and execute a .NET assembly", "sharpgen <code> [<spawnto path>, <spawnto args>]"},
		{"shell", "Execute a command on the agent using the host's default shell", "shell ping -c 3 8.8.8.8"},
		{"status", "Print the current status of the agent", ""},
		{"upload", "Upload a file to the agent", "upload <local_file> <remote_file>"},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// The help menu for the main or root Listeners menu
func menuHelpListenersMain() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listeners Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"delete", "Delete a named listener", "delete <listener_name>"},
		{"info", "Display all information about a listener", "info <listener_name>"},
		{"interact", "Interact with a named agent to modify it", "interact <listener_name>"},
		{"list", "List all created listeners", ""},
		{"main", "Return to the main menu", ""},
		{"start", "Start a named listener", "start <listener_name>"},
		{"stop", "Stop a named listener", "stop <listener_name>"},
		{"use", "Create a new listener by protocol type", "use [http,https,http2,http3,h2c]"},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// The help menu for Listeners template, or setup, menu
func menuHelpListenerSetup() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listener Setup Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the listeners menu", ""},
		{"execute", "Create and start the listener (alias)", ""},
		{"info", "Display all configurable information about a listener", ""},
		{"main", "Return to the main menu", ""},
		{"run", "Create and start the listener (alias)", ""},
		{"set", "Set a configurable option", "set <option_name>"},
		{"show", "Display all configurable information about a listener", ""},
		{"start", "Create and start the listener", ""},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// The help menu for a specific, instantiated, listener
func menuHelpListener() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listener Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the listeners menu", ""},
		{"delete", "Delete this listener", "delete <listener_name>"},
		{"info", "Display all configurable information the current listener", ""},
		{"main", "Return to the main menu", ""},
		{"restart", "Restart this listener", ""},
		{"set", "Set a configurable option", "set <option_name>"},
		{"show", "Display all configurable information about a listener", ""},
		{"start", "Start this listener", ""},
		{"status", "Get the server's current status", ""},
		{"stop", "Stop the listener", ""},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func displayJobTable(rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"ID", "Status", "Type", "Created", "Sent"})

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// displayTable writes arbitrary data rows to STDOUT
func displayTable(header []string, rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)

	if len(header) > 0 {
		table.SetHeader(header)
	}

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// confirm reads in a string and returns true if the string is y or yes but does not provide the prompt question
func confirm(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	//fmt.Print(color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)))
	MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)),
		Time:    time.Now().UTC(),
		Error:   false,
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error reading the input:\r\n%s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")
	yes := []string{"y", "yes", "-y", "-Y"}

	for _, match := range yes {
		if response == match {
			return true
		}
	}
	return false
}

// exit will prompt the user to confirm if they want to exit
func exit() {
	color.Red("[!]Quitting...")
	logging.Server("Shutting down Merlin due to user input")
	os.Exit(0)
}

func executeCommand(name string, arg []string) {

	cmd := exec.Command(name, arg...) // #nosec G204 Users can execute any arbitrary command by design

	out, err := cmd.CombinedOutput()

	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Executing system command...",
		Time:    time.Time{},
		Error:   false,
	}
	if err != nil {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: err.Error(),
			Time:    time.Time{},
			Error:   true,
		}
	} else {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Success,
			Message: fmt.Sprintf("%s", out),
			Time:    time.Time{},
			Error:   false,
		}
	}
}

func registerMessageChannel() {
	um := messages.Register(clientID)
	if um.Error {
		MessageChannel <- um
		return
	}
	if core.Debug {
		MessageChannel <- um
	}
}

func getUserMessages() {
	go func() {
		for {
			MessageChannel <- messages.GetMessageForClient(clientID)
		}
	}()
}

// printUserMessage is used to print all messages to STDOUT for command line clients
func printUserMessage() {
	go func() {
		for {
			m := <-MessageChannel
			switch m.Level {
			case messages.Info:
				fmt.Println(color.CyanString("\n[i] %s", m.Message))
			case messages.Note:
				fmt.Println(color.YellowString("\n[-] %s", m.Message))
			case messages.Warn:
				fmt.Println(color.RedString("\n[!] %s", m.Message))
			case messages.Debug:
				if core.Debug {
					fmt.Println(color.RedString("\n[DEBUG] %s", m.Message))
				}
			case messages.Success:
				fmt.Println(color.GreenString("\n[+] %s", m.Message))
			case messages.Plain:
				fmt.Println("\n" + m.Message)
			default:
				fmt.Println(color.RedString("\n[_-_] Invalid message level: %d\r\n%s", m.Level, m.Message))
			}
		}
	}()
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

type listener struct {
	id     uuid.UUID // Listener unique identifier
	name   string    // Listener unique name
	status string    // Listener server status
}
