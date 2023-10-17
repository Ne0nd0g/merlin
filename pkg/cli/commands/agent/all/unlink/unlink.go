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

package unlink

import (
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/completer"
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
	cmd.name = "unlink"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Task parent Agent to disconnect the child peer-to-peer Agent"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "unlink childAgentID"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link list\n" +
		"\t[-] Created job pJpbkMqphK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-28T11:59:32Z\n" +
		"\t[-] Results of job pJpbkMqphK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-28T11:59:54Z\n\n" +
		"\t[+] Peer-to-Peer Links (1)\n" +
		"\t0. tcp-bind:e718067d-bf44-4715-aae3-8c1142114e3d:127.0.0.1:7777\n\n" +
		"\tMerlin[agent][d02fff99-e37d-4220-b430-a1c199ad3bcb]» unlink e718067d-bf44-4715-aae3-8c1142114e3d\n" +
		"\t[-] Created job uLhDoRVtPY for agent d02fff99-e37d-4220-b430-a1c199ad3bcb at 2023-07-28T12:00:27Z\n" +
		"\t[-] Results of job uLhDoRVtPY for agent d02fff99-e37d-4220-b430-a1c199ad3bcb at 2023-07-28T12:00:41Z\n" +
		"\t[+] Successfully unlinked from tcp-bind Agent e718067d-bf44-4715-aae3-8c1142114e3d and closed the network connection"
	notes := "Depending on the child Agent type and configuration, the child Agent will remain running and " +
		"listening for new connections."
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {

	comp := readline.PcItem(c.name,
		readline.PcItemDynamic(completer.AgentLinkCompleter(id)),
	)
	return comp
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

	// Check for help first
	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
		return
	}

	// Validate the Agent ID
	if _, err := uuid.FromString(args[1]); err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("'%s' is not a valid Agent ID\n%s", args[1], c.help.Usage()))
		return
	}
	response.Message = rpc.UnlinkAgent(id, args[1:])
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
