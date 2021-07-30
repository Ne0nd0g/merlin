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
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Merlin
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
)

// listener is used to track the current listener the CLI is interacting with
var listener listenerInfo

// options is a map of configurable options for the current listener
var options map[string]string

type listenerInfo struct {
	id     uuid.UUID // Listener unique identifier
	name   string    // Listener unique name
	status string    // Listener server status
}

// handlerListener contains the logic to handle the "listener" menu commands, for an already instantiated listener
func handlerListener(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "back":
		Set(LISTENERS)
	case "delete":
		if core.Confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", listener.name)) {
			um := listenerAPI.Remove(listener.name)
			if !um.Error {
				listener = listenerInfo{}
				options = nil
				Set(LISTENERS)
			} else {
				core.MessageChannel <- um
			}
		}
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.Exit()
			}
		}
		if core.Confirm("Are you sure you want to exit?") {
			core.Exit()
		}
	case "help":
		helpListener()
	case "info", "show", "options":
		var um messages.UserMessage
		um, options = listenerAPI.GetListenerConfiguredOptions(listener.id)
		if um.Error {
			core.MessageChannel <- um
			break
		}
		statusMessage := listenerAPI.GetListenerStatus(listener.id)
		if statusMessage.Error {
			core.MessageChannel <- statusMessage
			break
		}
		listener.status = listenerAPI.GetListenerStatus(listener.id).Message
		if options != nil {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Value"})
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(true)
			table.SetBorder(true)

			for k, v := range options {
				table.Append([]string{k, v})
			}
			table.Append([]string{"Status", listener.status})
			table.Render()
		}
	case "interact":
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "main":
		Set(MAIN)
	case "restart":
		core.MessageChannel <- listenerAPI.Restart(listener.id)
		var um messages.UserMessage
		um, options = listenerAPI.GetListenerConfiguredOptions(listener.id)
		if um.Error {
			core.MessageChannel <- um
			break
		}
		core.Prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + options["Name"] + "\033[31m]»\033[0m ")
	case "sessions":
		header, rows := agentAPI.GetAgentsRows()
		core.DisplayTable(header, rows)
	case "set":
		core.MessageChannel <- listenerAPI.SetOption(listener.id, cmd)
	case "start":
		core.MessageChannel <- listenerAPI.Start(listener.name)
	case "status":
		core.MessageChannel <- listenerAPI.GetListenerStatus(listener.id)
	case "stop":
		core.MessageChannel <- listenerAPI.Stop(listener.name)
	default:
		if len(cmd) > 1 {
			core.ExecuteCommand(cmd[0], cmd[1:])
		} else {
			core.ExecuteCommand(cmd[0], []string{})
		}
	}
}

// completerListener returns a list of tab completable commands available in the "listener" menu
// This menu is used when interacting with an already instantiated listener
func completerListener() *readline.PrefixCompleter {
	// Listener Menu (a specific listener)
	return readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("delete"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("main"),
		readline.PcItem("remove"),
		readline.PcItem("restart"),
		readline.PcItem("sessions"),
		readline.PcItem("set",
			readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(options["Protocol"])),
		),
		readline.PcItem("show"),
		readline.PcItem("start"),
		readline.PcItem("status"),
		readline.PcItem("stop"),
	)
}

// helpListener displays help information for a specific, instantiated, listener
func helpListener() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listener Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the listeners menu", ""},
		{"delete", "Delete this listener", "delete <listener_name>"},
		{"info", "Display all configurable information the current listener", ""},
		{"interact", "Interact with an agent", "interact <agent_id>"},
		{"main", "Return to the main menu", ""},
		{"restart", "Restart this listener", ""},
		{"sessions", "List all agents session information. Alias for MSF users", ""},
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
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}
