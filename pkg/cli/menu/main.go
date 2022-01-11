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
	uuid "github.com/satori/go.uuid"
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
	serverCore "github.com/Ne0nd0g/merlin/pkg/core"
)

// handlerMain contains the logic to handle the "main" menu commands
func handlerMain(cmd []string) {
	switch cmd[0] {
	case "agent":
		if len(cmd) > 1 {
			switch strings.ToLower(cmd[1]) {
			case "interact":
				if len(cmd) > 2 {
					interactAgent(cmd[2])
				}
			case "list":
				header, rows := agentAPI.GetAgentsRows()
				core.DisplayTable(header, rows)
			default:
				core.MessageChannel <- messages.ErrorMessage(fmt.Sprintf("invalid agent command: %s", cmd[1]))
			}
		}
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
	case "clear", "c":
		core.MessageChannel <- agentAPI.ClearJobsCreated()
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
	case "group":
		if len(cmd) < 2 {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Not enough arguments provided",
				Time:    time.Now().UTC(),
				Error:   true,
			}
		} else {
			handlerGroup(cmd)
		}
	case "interact":
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "jobs":
		displayAllJobTable(agentAPI.GetJobs())
	case "listeners":
		Set(LISTENERS)
	case "queue":
		if len(cmd) > 2 {
			// Check for uuid match
			id, err := uuid.FromString(cmd[1])
			if err == nil {
				agent = id
				handlerAgent(cmd[2:])
			} else {
				found := false
				// Check for a group name match
				for _, groupName := range agentAPI.GroupListNames() {
					if groupName == cmd[1] {
						found = true
						for _, agentIDstr := range agentAPI.GroupList(groupName) {
							// We know it's a valid UUID because it's already in a group
							newID, _ := uuid.FromString(agentIDstr)
							agent = newID
							handlerAgent(cmd[2:])
						}
					}
				}

				// Nothing found
				if !found {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: "Couldn't find a user or group by that name",
						Time:    time.Now().UTC(),
						Error:   true,
					}
				}
			}
		} else {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Not enough arguments provided\n queue <agent|group> <command>",
				Time:    time.Now().UTC(),
				Error:   true,
			}
		}
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
					serverCore.Verbose = true
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
					serverCore.Debug = true
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
		readline.PcItem("clear"),
		readline.PcItem("group",
			readline.PcItem("list",
				readline.PcItemDynamic(completerGroup()),
			),
			readline.PcItem("add",
				readline.PcItemDynamic(agentListCompleter(),
					readline.PcItemDynamic(completerGroup()),
				),
			),
			readline.PcItem("remove",
				readline.PcItemDynamic(agentListCompleter(),
					readline.PcItemDynamic(completerGroup()),
				),
			),
		),
		readline.PcItem("help"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("jobs"),
		readline.PcItem("listeners"),
		readline.PcItem("queue",
			readline.PcItemDynamic(agentListCompleter()),
			readline.PcItemDynamic(completerGroup()),
		),
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
		{"clear", "clears all unset jobs", ""},
		{"group", "Add, remove, or list groups", "group <add | remove | list] <group>"},
		{"interact", "Interact with an agent", ""},
		{"jobs", "Display all unfinished jobs", ""},
		{"listeners", "Move to the listeners menu", ""},
		{"queue", "queue up commands for one, a group, or unknown agents", "queue <agentID> <command>"},
		{"quit", "Exit and close the Merlin server", "-y"},
		{"remove", "Remove or delete a DEAD agent from the server"},
		{"sessions", "Display a table of information about all checked-in agent sessions", ""},
		{"use", "Use a Merlin module", "module <module path>"},
		{"version", "Print the Merlin server version", ""},
		{"!", "Execute a command on the host operating system", "!<command> <args>"},
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

// displayAllJobTable displays a table of agent jobs along with their status
func displayAllJobTable(rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"Agent", "ID", "Command", "Status", "Created", "Sent"})

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// handlerGroup handles group commands from the main menu (add, remove list)
func handlerGroup(cmd []string) {
	switch cmd[1] {
	case "add":
		if len(cmd) != 4 {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Invalid number of arguments\ngroup add <agent> <group>",
				Time:    time.Now().UTC(),
				Error:   true,
			}
		} else {
			i, errUUID := uuid.FromString(cmd[2])
			if errUUID != nil {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("Invalid UUID: %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				core.MessageChannel <- agentAPI.GroupAdd(i, cmd[3])
			}
		}
	case "list":
		var data [][]string
		if len(cmd) == 3 { // List a specific group
			agents := agentAPI.GroupList(cmd[2])
			for _, a := range agents {
				data = append(data, []string{cmd[2], a})
			}
		} else {
			data = agentAPI.GroupListAll()
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Group", "Agent ID"})
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetRowLine(false)
		table.SetBorder(true)
		table.AppendBulk(data)
		table.Render()
	case "remove":
		if len(cmd) != 4 {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Invalid number of arguments\n group remove <agent> <group>",
				Time:    time.Now().UTC(),
				Error:   true,
			}
		} else {
			i, errUUID := uuid.FromString(cmd[2])
			if errUUID != nil {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("Invalid UUID: %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				core.MessageChannel <- agentAPI.GroupRemove(i, cmd[3])
			}
		}
	default:
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: "Invalid arguments\ngroup add <agent> <group>\ngroup list\ngroup remove <agent> <group>",
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
}

// completerGroup returns a list of group names for command line tab completion
func completerGroup() func(string) []string {
	return func(line string) []string {
		return agentAPI.GroupListNames()
	}
}
