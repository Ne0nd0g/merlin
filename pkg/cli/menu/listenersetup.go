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
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Merlin
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
)

// listenerType is used to track the type of listener the CLI is currently interacting with
var listenerType string

// handlerListenerSetup handles all of the logic for setting up a Listener
func handlerListenerSetup(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "back":
		Set(LISTENERS)
	case "help":
		helpListenerSetup()
	case "info", "show", "options":
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
	case "interact":
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "main":
		Set(MAIN)
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.Exit()
			}
		}
		if core.Confirm("Are you sure you want to exit?") {
			core.Exit()
		}
	case "sessions":
		header, rows := agentAPI.GetAgentsRows()
		core.DisplayTable(header, rows)
	case "set":
		if len(cmd) >= 2 {
			for k := range options {
				if cmd[1] == k {
					options[k] = strings.Join(cmd[2:], " ")
					m := fmt.Sprintf("set %s to: %s", k, strings.Join(cmd[2:], " "))
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: m,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				}
			}
		}
	case "start", "run", "execute":
		um, id := listenerAPI.NewListener(options)
		core.MessageChannel <- um
		if um.Error {
			return
		}
		if id == uuid.Nil {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "a nil Listener UUID was returned",
				Time:    time.Time{},
				Error:   true,
			}
			return
		}

		listener = listenerInfo{id: id, name: options["Name"]}
		startMessage := listenerAPI.Start(listener.name)
		listener.status = listenerAPI.GetListenerStatus(id).Message
		core.MessageChannel <- startMessage
		um, options = listenerAPI.GetListenerConfiguredOptions(listener.id)
		if um.Error {
			core.MessageChannel <- um
			break
		}
		Set(LISTENER)
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

// completerListenerSetup returns a list of tab completable commands available when creating or setting up a listener
func completerListenerSetup() *readline.PrefixCompleter {
	// Listener Setup Menu
	return readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("execute"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("main"),
		readline.PcItem("options"),
		readline.PcItem("run"),
		readline.PcItem("sessions"),
		readline.PcItem("set",
			readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(options["Protocol"])),
		),
		readline.PcItem("show"),
		readline.PcItem("start"),
		readline.PcItem("stop"),
	)
}

// helpListenerSetup displays the help information for configuring or setting up a listener
func helpListenerSetup() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listener Setup Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the listeners menu", ""},
		{"execute", "Create and start the listener (alias)", ""},
		{"info", "Display all configurable information about a listener", ""},
		{"interact", "Interact with an agent", "interact <agent_id>"},
		{"main", "Return to the main menu", ""},
		{"run", "Create and start the listener (alias)", ""},
		{"sessions", "List all agents session information. Alias for MSF users", ""},
		{"set", "Set a configurable option", "set <option_name>"},
		{"show", "Display all configurable information about a listener", ""},
		{"start", "Create and start the listener", ""},
		{"!", "Execute a command on the host operating system", "!<command> <args>"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}
