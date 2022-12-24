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
	"github.com/Ne0nd0g/merlin/pkg/services/listeners"
)

var listenerService = listeners.NewListenerService()

// handlerListeners handles all the logic for the root Listeners menu
func handlerListeners(cmd []string) {
	if len(cmd) <= 0 {
		return
	}
	switch strings.ToLower(cmd[0]) {
	case "configure":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				core.MessageChannel <- r
				return
			}
			if id == uuid.Nil {
				return
			}

			status := listenerAPI.GetListenerStatus(id).Message
			listener = listenerInfo{
				id:     id,
				name:   name,
				status: status,
			}
			Set(LISTENER)
		} else {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Note,
				Message: "you must select a listener to interact with",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	case "exit", "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				core.Exit()
			}
		}
		if core.Confirm("Are you sure you want to exit?") {
			core.Exit()
		}
	case "delete":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			um := listenerAPI.Exists(name)
			if um.Error {
				core.MessageChannel <- um
				return
			}
			if core.Confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", name)) {
				removeMessage := listenerAPI.Remove(name)
				core.MessageChannel <- removeMessage
				if removeMessage.Error {
					return
				}
				listener = listenerInfo{}
				options = nil
				Set(LISTENERS)
			}
		}
	case "help":
		helpListenersMain()
	case "info":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			um := listenerAPI.Exists(name)
			if um.Error {
				core.MessageChannel <- um
				return
			}
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				core.MessageChannel <- r
				return
			}
			if id == uuid.Nil {
				core.MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "a nil Listener UUID was returned",
					Time:    time.Time{},
					Error:   true,
				}
			}
			oMessage, options := listenerAPI.GetListenerConfiguredOptions(id)
			if oMessage.Error {
				core.MessageChannel <- oMessage
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
		if len(cmd) > 1 {
			interactAgent(cmd[1])
		}
	case "list":
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Name", "Description"})
		table.SetAlignment(tablewriter.ALIGN_CENTER)
		listeners := listenerService.Listeners()
		for _, l := range listeners {
			table.Append([]string{l.ID().String(), l.Name(), l.Description()})
		}
		fmt.Println()
		table.Render()
		fmt.Println()
	case "main", "back":
		Set(MAIN)
	case "sessions":
		header, rows := agentAPI.GetAgentsRows()
		core.DisplayTable(header, rows)
	case "start":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				core.MessageChannel <- r
				return
			}
			core.MessageChannel <- listenerAPI.Start(id)
		}
	case "stop":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				core.MessageChannel <- r
				return
			}
			core.MessageChannel <- listenerAPI.Stop(id)
		}
	case "use", "create":
		if len(cmd) >= 2 {
			var err error
			options, err = listenerService.DefaultOptions(cmd[1])
			if err != nil {
				core.MessageChannel <- messages.ErrorMessage(fmt.Sprintf("pkg/cli/menu/listeners.handlerListeners(): there was an error getting the default options for %s: %s", cmd[1], err))
				return
			}
			listenerType = cmd[1]
			Set(LISTENERSETUP)
		}
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

// completerListeners returns a list of tab completable commands available in the top-level listeners menu
func completerListeners() *readline.PrefixCompleter {
	// Listeners Main Menu (the root menu)
	return readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("configure",
			readline.PcItemDynamic(listenerService.List()),
		),
		readline.PcItem("create",
			readline.PcItemDynamic(listenerService.CLICompleter()),
		),
		readline.PcItem("delete",
			readline.PcItemDynamic(listenerService.List()),
		),
		readline.PcItem("help"),
		readline.PcItem("info",
			readline.PcItemDynamic(listenerService.List()),
		),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("list"),
		readline.PcItem("main"),
		readline.PcItem("sessions"),
		readline.PcItem("start",
			readline.PcItemDynamic(listenerService.List()),
		),
		readline.PcItem("stop",
			readline.PcItemDynamic(listenerService.List()),
		),
		readline.PcItem("use",
			readline.PcItemDynamic(listenerService.CLICompleter()),
		),
	)
}

// helpListenersMain displays the help menu for the main or root Listeners menu
func helpListenersMain() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listeners Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"configure", "Interact with and configure a named listener to modify it", "configure <listener_name>"},
		{"delete", "Delete a named listener", "delete <listener_name>"},
		{"info", "Display all information about a listener", "info <listener_name>"},
		{"interact", "Interact with an agent", "interact <agent_id>"},
		{"list", "List all created listeners", ""},
		{"main", "Return to the main menu", ""},
		{"sessions", "List all agents session information. Alias for MSF users", ""},
		{"start", "Start a named listener", "start <listener_name>"},
		{"stop", "Stop a named listener", "stop <listener_name>"},
		{"use", "Create a new listener by protocol type", "use [http,https,http2,http3,h2c]"},
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
