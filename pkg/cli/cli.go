// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

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
	"strconv"
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
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/modules"
	"github.com/Ne0nd0g/merlin/pkg/modules/shellcode"
)

// Global Variables
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
					color.Blue(banner.MerlinBanner1)
					color.Blue("\t\t   Version: %s", merlin.Version)
				case "help":
					menuHelpMain()
				case "?":
					menuHelpMain()
				case "exit", "quit":
					exit()
				case "interact":
					if len(cmd) > 1 {
						i := []string{"interact"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
				case "remove":
					if len(cmd) > 1 {
						i := []string{"remove"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
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
								message("warn", err.Error())
							} else {
								message("success", s)
							}
						} else {
							s, err := shellModule.SetOption(cmd[1], cmd[2])
							if err != nil {
								message("warn", err.Error())
							} else {
								message("success", s)
							}
						}
					}
				case "reload":
					menuSetModule(strings.TrimSuffix(strings.Join(shellModule.Path, "/"), ".json"))
				case "run":
					var m string
					r, err := shellModule.Run()
					if err != nil {
						message("warn", err.Error())
						break
					}
					if len(r) <= 0 {
						message("warn", fmt.Sprintf("The %s module did not return a command to task an"+
							" agent with", shellModule.Name))
						break
					}
					if strings.ToLower(shellModule.Type) == "standard" {
						m, err = agents.AddJob(shellModule.Agent, "cmd", r)
					} else {
						m, err = agents.AddJob(shellModule.Agent, r[0], r[1:])
					}

					if err != nil {
						message("warn", "There was an error adding the job to the specified agent")
						message("warn", err.Error())
					} else {
						message("note", fmt.Sprintf("Created job %s for agent %s at %s",
							m, shellModule.Agent, time.Now().UTC().Format(time.RFC3339)))
					}

				case "back", "main":
					menuSetMain()
				case "exit", "quit":
					exit()
				case "?", "help":
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
					if len(cmd) > 1 {
						m, err := agents.AddJob(shellAgent, "cmd", cmd[1:])
						if err != nil {
							message("warn", err.Error())
						} else {
							message("note", fmt.Sprintf("Created job %s for agent %s at %s",
								m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
						}
					}
				case "download":
					if len(cmd) >= 2 {
						arg := strings.Join(cmd[1:], " ")
						argS, errS := shellwords.Parse(arg)
						if errS != nil {
							message("warn", fmt.Sprintf("There was an error parsing command line "+
								"argments: %s\r\n%s", line, errS.Error()))
							break
						}
						if len(argS) >= 1 {
							m, err := agents.AddJob(shellAgent, "download", argS[0:1])
							if err != nil {
								message("warn", err.Error())
								break
							} else {
								message("note", fmt.Sprintf("Created job %s for agent %s at %s",
									m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
							}
						}
					} else {
						message("warn", "Invalid command")
						message("info", "download <remote_file_path>")
					}
				case "execute-shellcode":
					if len(cmd) > 2 {
						options := make(map[string]string)
						switch strings.ToLower(cmd[1]) {
						case "self":
							options["method"] = "self"
							options["pid"] = ""
							options["shellcode"] = strings.Join(cmd[2:], " ")
						case "remote":
							if len(cmd) > 3 {
								options["method"] = "remote"
								options["pid"] = cmd[2]
								options["shellcode"] = strings.Join(cmd[3:], " ")
							} else {
								message("warn", "Not enough arguments. Try using the help command")
								message("info", "execute-shellcode remote <pid> <shellcode>")
								break
							}
						case "rtlcreateuserthread":
							if len(cmd) > 3 {
								options["method"] = "rtlcreateuserthread"
								options["pid"] = cmd[2]
								options["shellcode"] = strings.Join(cmd[3:], " ")
							} else {
								message("warn", "Not enough arguments. Try using the help command")
								message("info", "execute-shellcode RtlCreateUserThread <pid> <shellcode>")
								break
							}
						case "userapc":
							if len(cmd) > 3 {
								options["method"] = "userapc"
								options["pid"] = cmd[2]
								options["shellcode"] = strings.Join(cmd[3:], " ")
							} else {
								message("warn", "Not enough arguments. Try using the help command")
								message("info", "execute-shellcode UserAPC <pid> <shellcode>")
								break
							}
						default:
							message("warn", "invalid method provided")
						}
						if len(options) > 0 {
							sh, errSh := shellcode.Parse(options)
							if errSh != nil {
								message("warn", fmt.Sprintf("there was an error parsing the shellcode:\r\n%s", errSh.Error()))
								break
							}
							m, err := agents.AddJob(shellAgent, sh[0], sh[1:])
							if err != nil {
								message("warn", err.Error())
								break
							} else {
								message("note", fmt.Sprintf("Created job %s for agent %s at %s",
									m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
							}
						}
					} else {
						message("warn", "not enough arguments were provided")
						message("info", "execute-shellcode self <shellcode>")
						message("info", "execute-shellcode remote <pid> <shellcode>")
						message("info", "execute-shellcode RtlCreateUserThread <pid> <shellcode>")
						break
					}
				case "exit", "quit":
					exit()
				case "?", "help":
					menuHelpAgent()
				case "info":
					agents.ShowInfo(shellAgent)
				case "kill":
					if len(cmd) > 0 {
						m, err := agents.AddJob(shellAgent, "kill", cmd[0:])
						menuSetMain()
						if err != nil {
							message("warn", err.Error())
						} else {
							message("note", fmt.Sprintf("Created job %s for agent %s at %s",
								m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
						}
					}
				case "ls":
					var m string
					if len(cmd) > 1 {
						arg := strings.Join(cmd[0:], " ")
						argS, errS := shellwords.Parse(arg)
						if errS != nil {
							message("warn", fmt.Sprintf("There was an error parsing command line "+
								"argments: %s\r\n%s", line, errS.Error()))
							break
						}
						m, err = agents.AddJob(shellAgent, "ls", argS)
						if err != nil {
							message("warn", err.Error())
							break
						}
					} else {
						m, err = agents.AddJob(shellAgent, cmd[0], cmd)
						if err != nil {
							message("warn", err.Error())
							break
						}
					}
					message("note", fmt.Sprintf("Created job %s for agent %s at %s",
						m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
				case "cd":
					var m string
					if len(cmd) > 1 {
						arg := strings.Join(cmd[0:], " ")
						argS, errS := shellwords.Parse(arg)
						if errS != nil {
							message("warn", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", line, errS.Error()))
							break
						}
						m, err = agents.AddJob(shellAgent, "cd", argS)
						if err != nil {
							message("warn", err.Error())
							break
						}
					} else {
						m, err = agents.AddJob(shellAgent, "cd", cmd)
						if err != nil {
							message("warn", err.Error())
							break
						}
					}
					message("note", fmt.Sprintf("Created job %s for agent %s at %s",
						m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
				case "pwd":
					var m string
					m, err = agents.AddJob(shellAgent, "pwd", cmd)
					if err != nil {
						message("warn", err.Error())
						break
					}
					message("note", fmt.Sprintf("Created job %s for agent %s at %s",
						m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
				case "main":
					menuSetMain()
				case "set":
					if len(cmd) > 1 {
						switch cmd[1] {
						case "killdate":
							if len(cmd) > 2 {
								_, errU := strconv.ParseInt(cmd[2], 10, 64)
								if errU != nil {
									message("warn", fmt.Sprintf("There was an error converting %s to an"+
										" int64", cmd[2]))
									message("info", "Kill date takes in a UNIX epoch timestamp such as"+
										" 811123200 for September 15, 1995")
									break
								}
								m, err := agents.AddJob(shellAgent, "killdate", cmd[1:])
								if err != nil {
									message("warn", fmt.Sprintf("There was an error adding a killdate "+
										"agent control message:\r\n%s", err.Error()))
								} else {
									message("note", fmt.Sprintf("Created job %s for agent %s at %s",
										m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
								}
							}
						case "maxretry":
							if len(cmd) > 2 {
								m, err := agents.AddJob(shellAgent, "maxretry", cmd[1:])
								if err != nil {
									message("warn", err.Error())
								} else {
									message("note", fmt.Sprintf("Created job %s for agent %s at %s",
										m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
								}
							}
						case "padding":
							if len(cmd) > 2 {
								m, err := agents.AddJob(shellAgent, "padding", cmd[1:])
								if err != nil {
									message("warn", err.Error())
								} else {
									message("note", fmt.Sprintf("Created job %s for agent %s at %s",
										m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
								}
							}
						case "sleep":
							if len(cmd) > 2 {
								m, err := agents.AddJob(shellAgent, "sleep", cmd[1:])
								if err != nil {
									message("warn", err.Error())
								} else {
									message("note", fmt.Sprintf("Created job %s for agent %s at %s",
										m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
								}
							}
						case "skew":
							if len(cmd) > 2 {
								m, err := agents.AddJob(shellAgent, "skew", cmd[1:])
								if err != nil {
									message("warn", err.Error())
								} else {
									message("note", fmt.Sprintf("Created job %s for agent %s at %s",
										m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
								}
							}
						}
					}
				case "shell":
					if len(cmd) > 1 {
						m, err := agents.AddJob(shellAgent, "cmd", cmd[1:])
						if err != nil {
							message("warn", err.Error())
						} else {
							message("note", fmt.Sprintf("Created job %s for agent %s at %s",
								m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
						}
					}
				case "status":
					status := agents.GetAgentStatus(shellAgent)
					if status == "Active" {
						color.Green("Active")
					} else if status == "Delayed" {
						color.Yellow("Delayed")
					} else if status == "Dead" {
						color.Red("Dead")
					} else {
						color.Blue(status)
					}
				case "upload":
					if len(cmd) >= 3 {
						arg := strings.Join(cmd[1:], " ")
						argS, errS := shellwords.Parse(arg)
						if errS != nil {
							message("warn", fmt.Sprintf("There was an error parsing command line "+
								""+
								"argments: %s\r\n%s", line, errS.Error()))
							break
						}
						if len(argS) >= 2 {
							_, errF := os.Stat(argS[0])
							if errF != nil {
								message("warn", fmt.Sprintf("There was an error accessing the source "+
									"upload file:\r\n%s", errF.Error()))
								break
							}
							m, err := agents.AddJob(shellAgent, "upload", argS[0:2])
							if err != nil {
								message("warn", err.Error())
								break
							} else {
								message("note", fmt.Sprintf("Created job %s for agent %s at %s",
									m, shellAgent, time.Now().UTC().Format(time.RFC3339)))
							}
						}
					} else {
						message("warn", "Invalid command")
						message("info", "upload local_file_path remote_file_path")
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

func menuAgent(cmd []string) {
	switch cmd[0] {
	case "list":
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Agent GUID", "Platform", "User", "Host", "Transport", "Status"})
		table.SetAlignment(tablewriter.ALIGN_CENTER)
		for k, v := range agents.Agents {
			// Convert proto (i.e. h2 or hq) to user friendly string
			var proto string
			if v.Proto == "https" {
				proto = "HTTP/1.1 (https)"
			} else if v.Proto == "h2" {
				proto = "HTTP/2 (h2)"
			} else if v.Proto == "hq" {
				proto = "QUIC (hq)"
			}

			table.Append([]string{k.String(), v.Platform + "/" + v.Architecture, v.UserName,
				v.HostName, proto, agents.GetAgentStatus(k)})
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
	case "remove":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				message("warn", fmt.Sprintf("There was an error interacting with agent %s", cmd[1]))
			} else {
				errRemove := agents.RemoveAgent(i)
				if errRemove != nil {
					message("warn", errRemove.Error())
				} else {
					message("info", fmt.Sprintf("Agent %s was removed from the server at %s",
						cmd[1], time.Now().UTC().Format(time.RFC3339)))
				}
			}
		}
	}
}

func menuSetAgent(agentID uuid.UUID) {
	for k := range agents.Agents {
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
		var mPath = path.Join(core.CurrentDir, "data", "modules", cmd+".json")
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
				readline.PcItemDynamic(agents.GetAgentList()),
			),
		),
		readline.PcItem("banner"),
		readline.PcItem("help"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agents.GetAgentList()),
		),
		readline.PcItem("remove",
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
		readline.PcItem("execute-shellcode",
			readline.PcItem("self"),
			readline.PcItem("remote"),
			readline.PcItem("RtlCreateUserThread"),
		),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("kill"),
		readline.PcItem("ls"),
		readline.PcItem("cd"),
		readline.PcItem("pwd"),
		readline.PcItem("main"),
		readline.PcItem("shell"),
		readline.PcItem("set",
			readline.PcItem("killdate"),
			readline.PcItem("maxretry"),
			readline.PcItem("padding"),
			readline.PcItem("skew"),
			readline.PcItem("sleep"),
		),
		readline.PcItem("status"),
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
}

func menuHelpMain() {
	color.Yellow("Merlin C2 Server (version %s)", merlin.Version)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Main Menu Help")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"agent", "Interact with agents or list agents", "interact, list"},
		{"banner", "Print the Merlin banner", ""},
		{"exit", "Exit and close the Merlin server", ""},
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
	message("info", "Visit the wiki for additional information https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Main-Menu")
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
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	message("info", "Visit the wiki for additional information https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Module-Menu")
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
		{"cmd", "Execute a command on the agent (DEPRECIATED)", "cmd ping -c 3 8.8.8.8"},
		{"back", "Return to the main menu", ""},
		{"download", "Download a file from the agent", "download <remote_file>"},
		{"execute-shellcode", "Execute shellcode", "self, remote <pid>, RtlCreateUserThread <pid>"},
		{"info", "Display all information about the agent", ""},
		{"kill", "Instruct the agent to die or quit", ""},
		{"ls", "List directory contents", "ls /etc OR ls C:\\\\Users"},
		{"main", "Return to the main menu", ""},
		{"pwd", "Display the current working directory", "pwd"},
		{"set", "Set the value for one of the agent's options", "killdate, maxretry, padding, skew, sleep"},
		{"shell", "Execute a command on the agent", "shell ping -c 3 8.8.8.8"},
		{"status", "Print the current status of the agent", ""},
		{"upload", "Upload a file to the agent", "upload <local_file> <remote_file>"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	message("info", "Visit the wiki for additional information "+
		"https://github.com/Ne0nd0g/merlin/wiki/Merlin-Server-Agent-Menu")
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
func message(level string, message string) {
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

// confirm reads in string and returns true if the string is y or yes but does not provide the prompt question
func confirm(response string) bool {

	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")
	yes := []string{"y", "yes"}

	for _, match := range yes {
		if response == match {
			return true
		}
	}

	return false
}

// exit will prompt the user to confirm if they want to exit
func exit() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are you sure you want to exit? [yes/NO]: ")
	response, err := reader.ReadString('\n')
	if err != nil {
		message("warn", fmt.Sprintf("There was an error reading the input:\r\n%s", err.Error()))
	}
	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")

	if confirm(response) {
		color.Red("[!]Quitting")
		logging.Server("Shutting down Merlin Server due to user input")
		os.Exit(0)
	}
}

func executeCommand(name string, arg []string) {
	cmd := exec.Command(name, arg...) // #nosec G204 Users can execute any arbitrary command by design

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
