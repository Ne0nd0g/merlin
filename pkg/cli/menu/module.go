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
	"path"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"

	// Merlin
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/modules"
)

// module is used to track the current module that the CLI is interacting with
var module modules.Module

// handlerModule contains the logic to handle the "module" menu commands
func handlerModule(cmd []string) {
	if len(cmd) <= 0 {
		return
	}
	switch cmd[0] {
	case "back", "main":
		Set(MAIN)
	case "help", "?":
		helpModule()
	case "info":
		module.ShowInfo()
	case "interact":
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.Exit()
			}
		}
		if core.Confirm("Are you sure you want to quit the server?") {
			core.Exit()
		}
	case "reload":
		setModule(strings.TrimSuffix(strings.Join(module.Path, "/"), ".json"))
	case "run":
		modMessages := moduleAPI.RunModule(module)
		for _, message := range modMessages {
			core.MessageChannel <- message
		}
	case "sessions":
		header, rows := agentAPI.GetAgentsRows()
		core.DisplayTable(header, rows)
	case "set":
		if len(cmd) > 2 {
			if cmd[1] == "Agent" {
				s, err := module.SetAgent(cmd[2])
				if err != nil {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: err.Error(),
						Time:    time.Now().UTC(),
						Error:   true,
					}
				} else {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: s,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				}
			} else {
				s, err := module.SetOption(cmd[1], cmd[2:])
				if err != nil {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: err.Error(),
						Time:    time.Now().UTC(),
						Error:   true,
					}
				} else {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: s,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				}
			}
		}
	case "show":
		if len(cmd) > 1 {
			switch cmd[1] {
			case "info":
				module.ShowInfo()
			case "options":
				module.ShowOptions()
			}
		}
	case "unset":
		if len(cmd) >= 2 {
			s, err := module.SetOption(cmd[1], nil)
			if err != nil {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: err.Error(),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Success,
					Message: s,
					Time:    time.Now().UTC(),
					Error:   false,
				}
			}
		}
	default:
		if len(cmd) > 1 {
			core.ExecuteCommand(cmd[0], cmd[1:])
		} else {
			core.ExecuteCommand(cmd[0], []string{})
		}
	}
}

// completerModule returns a list of tab completable commands available in the "module" menu
func completerModule() *readline.PrefixCompleter {
	// Module Menu
	return readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("main"),
		readline.PcItem("reload"),
		readline.PcItem("run"),
		readline.PcItem("sessions"),
		readline.PcItem("show",
			readline.PcItem("options"),
			readline.PcItem("info"),
		),
		readline.PcItem("set",
			readline.PcItem("Agent",
				readline.PcItem("all"),
				readline.PcItemDynamic(agentListCompleter()),
			),
			readline.PcItemDynamic(module.GetOptionsList()),
		),
		readline.PcItem("unset",
			readline.PcItemDynamic(module.GetOptionsList()),
		),
	)
}

// helpModule displays help information for the modules menu
func helpModule() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Module Menu Help")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"info", "Show information about a module"},
		{"interact", "Interact with an agent", "interact <agent_id>"},
		{"main", "Return to the main menu", ""},
		{"reload", "Reloads the module to a fresh clean state"},
		{"run", "Run or execute the module", ""},
		{"sessions", "List all agents session information. Alias for MSF users", ""},
		{"set", "Set the value for one of the module's options", "<option name> <option value>"},
		{"show", "Show information about a module or its options", "info, options"},
		{"unset", "Clear a module option to empty", "<option name>"},
		{"*", "Anything else will be execute on the host operating system", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/modules.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// setModule is used to validate the selected input module exists and switch to its menu
func setModule(cmd string) {
	if len(cmd) > 0 {
		mPath := path.Join(core.CurrentDir, "data", "modules", cmd+".json")
		um, m := moduleAPI.GetModule(mPath)
		if um.Error {
			core.MessageChannel <- um
			return
		}
		if m.Name != "" {
			module = m
			Set(MODULE)
		}
	}
}
