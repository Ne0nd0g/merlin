/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package socks

import (
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	"github.com/Ne0nd0g/merlin/pkg/cli/services/rpc"
)

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string      // name is the name of the command
	help   help.Help   // help is the Help structure for the command
	menus  []menu.Menu // menu is the Menu the command can be used in
	native bool        // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS       // os is the supported operating system the Agent command can be executed on
}

// NewCommand is a factory that builds and returns a Command structure that implements the Command interface
func NewCommand() *Command {
	var cmd Command
	cmd.name = "socks"
	cmd.menus = []menu.Menu{menu.AGENT, menu.MAIN}
	cmd.os = os.LOCAL
	description := "Start, stop, or list a SOCKS5 server on the Merlin server"
	usage := "socks {list | start [interface:]port agentID |stop [interface:]port agentID}"
	example := ""
	notes := "There can only be one SOCKS5 listener per agent.\n" +
		"\tSOCKS5 listeners do not require authentication. Control access accordingly using firewall rules or SSH tunnels."
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {
	completer := readline.PcItem("socks",
		readline.PcItem("list"),
		readline.PcItem("start",
			readline.PcItem("127.0.0.1:9050",
				readline.PcItemDynamic(completerAgent()),
			),
		),
		readline.PcItem("stop",
			readline.PcItem("127.0.0.1:9050",
				readline.PcItemDynamic(completerAgent()),
			),
		),
	)
	return completer
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()))
		return
	}

	// If the command was executed from the Agent menu, and a UUID wasn't provided, add it to the arguments
	if m == menu.AGENT {
		if len(args) < 4 {
			args = append(args, id.String())
		}
	}

	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		case "list":
			return c.List(args[1:])
		case "start":
			return c.Start(args[1:])
		case "stop":
			return c.Stop(args[1:])
		default:
			response.Message = message.NewUserMessage(message.Warn, fmt.Sprintf("'%s' command does not support '%s' argument\n%s", c, args[1], c.help.Usage()))
		}
	}
	return
}

func (c *Command) Start(args []string) (response commands.Response) {
	description := "Start a SOCKS5 server on the Merlin server for the provided Agent ID"
	example := "Merlin» socks start 9050 c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Started SOCKS listener for agent c1090dbc-f2f7-4d90-a241-86e0c0217786] on 127.0.0.1:9050\n"
	usage := "socks start [interface:]port agentID"
	notes := "If a network interface is not provided, the loopback interface (127.0.0.1) will be used\n" +
		"\tUse tab completion to cycle through available agents"
	h := help.NewHelp(description, example, notes, usage)

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s start' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// Validate at least two arguments, in addition to the command, was provided
	if len(args) < 3 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s start' command requires at least two argument\n%s", c, h.Usage()))
		return
	}

	// 0. start
	// 1. interface:port
	// 2. agentUUID
	// Parse Agent UUID
	id, err := uuid.FromString(args[2])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing '%s' to a UUID: %s\n%s", args[2], err, h.Usage()))
		return
	}
	response.Message = rpc.Socks(id, args)
	return
}

func (c *Command) Stop(args []string) (response commands.Response) {

	description := "Stop and remove a SOCKS5 server on the Merlin server for the provided Agent ID"
	example := "Merlin» socks stop 9050 c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Successfully stopped SOCKS listener for agent c1090dbc-f2f7-4d90-a241-86e0c0217786] on 127.0.0.1:9050\n"
	usage := "socks stop [interface:]port agentID"
	notes := "Use tab completion to cycle through available agents"
	h := help.NewHelp(description, example, notes, usage)

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s stop' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// Validate at least two arguments, in addition to the command, was provided
	if len(args) < 3 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s stop' command requires at least two argument\n%s", c, h.Usage()))
		return
	}

	// 0. stop
	// 1. interface:port
	// 2. agentUUID
	// Parse Agent UUID
	id, err := uuid.FromString(args[2])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing '%s' to a UUID: %s\n%s", args[2], err, h.Usage()))
		return
	}
	response.Message = rpc.Socks(id, args)
	return
}

func (c *Command) List(args []string) (response commands.Response) {
	description := "List active SOCKS5 listeners per agent"
	example := "Merlin» socks list\n" +
		"\t        Agent                           Interface:Port\n" +
		"\t==========================================================\n" +
		"\tc1090dbc-f2f7-4d90-a241-86e0c0217786    127.0.0.1:9050\n" +
		"\t7be9defd-29b8-46ee-8d38-0f3805e9233f    [::]:9051\n" +
		"\t6d8a3a59-e484-40b3-977b-530b351106a6    192.168.1.100:9053"
	usage := "socks list"
	notes := "If the SOCKS5 listener was configured to listen on all interfaces (e.g., 0.0.0.0), then the interface will be listed as [::]:"
	h := help.NewHelp(description, example, notes, usage)

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s list' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}
	response.Message = rpc.Socks(uuid.Nil, args)
	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	return c.help
}

// Menu checks to see if the command is supported for the provided menu
func (c *Command) Menu(m menu.Menu) bool {
	for _, v := range c.menus {
		if v == m || v == menu.ALLMENUS {
			return true
		}
	}
	return false
}

// OS returns the supported operating system the Agent command can be executed on
func (c *Command) OS() os.OS {
	return c.os
}

// String returns the unique name of the command as a string
func (c *Command) String() string {
	return c.name
}

// completerAgent returns a list of agents that exist and is used for command line tab completion
func completerAgent() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		agentList, err := rpc.GetAgents()
		// If there is an error, return empty so this doesn't break the CLI
		if err != nil {
			return a
		}
		for _, id := range agentList {
			a = append(a, id.String())
		}
		return a
	}
}
