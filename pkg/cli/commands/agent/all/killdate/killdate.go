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

package killdate

import (
	// Standard
	"fmt"
	"strconv"
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
	cmd.name = "killdate"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Set the epoch date/time the agent will quit running"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "killdate epochDateTime"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» killdate 811123200\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»\n" +
		"\t[-]Created job utpISXXXbl for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n"
	notes := "Killdate is a UNIX timestamp that denotes a time the executable will not run after " +
		"(if it is 0 it will not be used). Killdate is checked before the agent performs each checkin, " +
		"including before the initial checkin.\n\n" +
		"\tKilldate can be set in the agent/agent.go file before compiling, in the New function instantiation of a " +
		"new agent. One scenario for using the killdate feature is an agent is persisted as a service and you want it " +
		"to stop functioning after a certain date, in case the target organization fails to remediate the malicious " +
		"service. Using killdate here would stop the agent from functioning after a certain specified UNIX system time.\n\n" +
		"\tThe Killdate can also be set or changed for running agents using the set killdate command from the agent menu. " +
		"This will only modify the killdate for the running agent in memory and will not update the compiled binary file." +
		" http://unixtimestamp.50x.eu/ can be used to generate a UNIX timestamp.\n\n" +
		"\tA UNIX timestamp of 0 will read like 1970-01-01T00:00:00Z in the agent info table."
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {

	return readline.PcItem(c.name)
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

	// Validate the argument is a valid integer
	_, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("'%s' is not a valid integer\n%s", args[1], c.help.Usage()))
		return
	}

	response.Message = rpc.KillDate(id, args)
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
