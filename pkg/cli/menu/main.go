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

	// Merlin
	merlin "github.com/Ne0nd0g/merlin/pkg"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
)

// handlerMain contains the logic to handle the "main" menu commands
func handlerMain(cmd []string) {
	switch cmd[0] {
	case "banner":
		m := "\n"
		m += color.BlueString(banner.MerlinBanner1)
		m += color.BlueString("\r\n\t\t   Version: %s", merlin.Version)
		m += color.BlueString("\r\n\t\t   Build: %s\n", merlin.Build)
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Plain,
			Message: m,
			Time:    time.Now().UTC(),
			Error:   false,
		}
	case "banner2":
		m := "\n"
		m += color.WhiteString(banner.MerlinBanner2)
		m += color.WhiteString("\r\n\t\t   Version: %s", merlin.Version)
		m += color.WhiteString("\r\n\t\t   Build: %s", merlin.Build)
		m += color.WhiteString("\r\n\t\t   Codename: Gandalf\n")
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Plain,
			Message: m,
			Time:    time.Now().UTC(),
			Error:   false,
		}
	case "help", "?":
		helpMain()
	case "exit", "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.Exit()
			}
		}
		if core.Confirm("Are you sure you want to quit the server?") {
			core.Exit()
		}
	case "interact":
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "listeners":
		Set(LISTENERS)
	case "remove":
		if len(cmd) > 1 {
			removeAgent(cmd[1])
		}
	case "sessions":
		header, rows := agentAPI.GetAgentsRows()
		core.DisplayTable(header, rows)
	case "set":
		if len(cmd) > 2 {
			switch cmd[1] {
			case "verbose":
				if strings.ToLower(cmd[2]) == "true" {
					core.Verbose = true
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: "Verbose output enabled",
						Time:    time.Now(),
						Error:   false,
					}
				} else if strings.ToLower(cmd[2]) == "false" {
					core.Verbose = false
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: "Verbose output disabled",
						Time:    time.Now(),
						Error:   false,
					}
				}
			case "debug":
				if strings.ToLower(cmd[2]) == "true" {
					core.Debug = true
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: "Debug output enabled",
						Time:    time.Now().UTC(),
						Error:   false,
					}
				} else if strings.ToLower(cmd[2]) == "false" {
					core.Debug = false
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: "Debug output disabled",
						Time:    time.Now().UTC(),
						Error:   false,
					}
				}
			}
		}
	case "use":
		moduleSubMenu(cmd[1:])
	case "version":
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Plain,
			Message: color.BlueString("Merlin version: %s\n", merlin.Version),
			Time:    time.Now().UTC(),
			Error:   false,
		}
	case "":
	default:
		if len(cmd) > 1 {
			core.ExecuteCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			core.ExecuteCommand(cmd[0], x)
		}
	}
}

// completerMain returns a list of tab completable commands available in the "main" menu
func completerMain() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
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
		readline.PcItem("quit"),
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
}

// moduleSubMenu handles commands that interact with modules but from the main menu
func moduleSubMenu(cmd []string) {
	if len(cmd) > 0 {
		switch cmd[0] {
		case "module":
			if len(cmd) > 1 {
				setModule(cmd[1])
			} else {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "Invalid module",
					Time:    time.Now().UTC(),
					Error:   false,
				}
			}
		case "":
		default:
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Note,
				Message: "Invalid 'use' command",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	} else {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Note,
			Message: "Invalid 'use' command",
			Time:    time.Now().UTC(),
			Error:   false,
		}
	}
}

// helpMain displays the help information for the "main" menu
func helpMain() {
	core.MessageChannel <- messages.UserMessage{
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
		{"listeners", "Move to the listeners menu", ""},
		{"interact", "Interact with an agent", ""},
		{"quit", "Exit and close the Merlin server", ""},
		{"remove", "Remove or delete a DEAD agent from the server"},
		{"sessions", "List all agents session information", ""},
		{"use", "Use a function of Merlin", "module"},
		{"version", "Print the Merlin server version", ""},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/main.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}
