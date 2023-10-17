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

package start

import (
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/run"
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
	cmd.name = "start"
	cmd.menus = []menu.Menu{menu.LISTENER, menu.LISTENERS, menu.LISTENERSETUP}
	cmd.os = os.LOCAL
	description := "Create and start the listener on the server"
	usage := "start listenerID"
	example := "Merlin[listeners]» use https\n" +
		"\tMerlin[listeners][https]» start\n\n" +
		"\t[!] Insecure publicly distributed Merlin x.509 testing certificate in use for https server on 127.0.0.1:443\n" +
		"\tAdditional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates\n\n" +
		"\t[+] Default listener was created with an ID of: 632db67c-7045-462f-bf09-aea90272aed5\n" +
		"\tMerlin[listeners][Default]»\n" +
		"\t[+] Started HTTPS listener on 127.0.0.1:443\n" +
		"\tMerlin[listeners][Default]»"
	notes := "This command is an alias for the 'run' command"
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
		case "help", "-h", "--help", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		}
	}
	switch m {
	case menu.LISTENER:
		response.Message = rpc.StartListener(id)
	case menu.LISTENERS:
		return c.DoListeners(arguments)
	case menu.LISTENERSETUP:
		return run.NewCommand().Do(m, id, arguments)
	}
	return
}

func (c *Command) DoListeners(arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	if len(args) < 2 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument from this menu\nstart listenerID", c))
		return
	}

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		}
	}
	// Parse the UUID
	id, err := uuid.FromString(args[1])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing the UUID '%s': %s\n%s", args[1], err, c.help.Usage()))
		return
	}
	response.Message = rpc.StartListener(id)
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
