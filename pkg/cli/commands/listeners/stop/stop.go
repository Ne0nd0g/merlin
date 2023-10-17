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

package stop

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
	cmd.name = "stop"
	cmd.menus = []menu.Menu{menu.LISTENER, menu.LISTENERS}
	cmd.os = os.LOCAL
	description := "Stop a listener from running"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "stop [listenerID]"
	example := "Merlin[listeners]» list \n\n" +
		"\t                   ID                  |       NAME       |   INTERFACE   | PROTOCOL | STATUS  |      DESCRIPTION       \n" +
		"\t+--------------------------------------+------------------+---------------+----------+---------+-----------------------+\n" +
		"\t  9f633d2e-de1b-4ad5-8693-b689164f066e | My HTTP Listener | 127.0.0.1:443 | HTTPS    | Running | Default HTTP Listener  \n\n" +
		"\tMerlin[listeners]» stop 9f633d2e-de1b-4ad5-8693-b689164f066e\n" +
		"\tMerlin[listeners]»  \n" +
		"\t[+] 9f633d2e-de1b-4ad5-8693-b689164f066e listener was stopped\n"
	notes := "Use tab to cycle through available listeners"
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

func (c *Command) Completer(m menu.Menu, id uuid.UUID) (comp readline.PrefixCompleterInterface) {

	switch m {
	case menu.LISTENER:
		comp = readline.PcItem(c.name)
	case menu.LISTENERS:
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(completer.ListenerListCompleter()),
		)
	default:
		comp = readline.PcItem(c.name)
	}
	return
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		}
	}

	switch m {
	case menu.LISTENERS:
		if len(args) < 2 {
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument from this menu\nstop listenerID", c))
			return
		}
		// Parse the UUID
		var err error
		id, err = uuid.FromString(args[1])
		if err != nil {
			response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing the UUID '%s': %s\n%s", args[1], err, c.help.Usage()))
			return
		}
	}
	response.Message = rpc.ListenerStop(id)
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
