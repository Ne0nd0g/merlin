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

package make_token

import (
	// Standard
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/token"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
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
	cmd.name = "make_token"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Create a new Windows access token"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "make_token DOMAIN\\USERNAME PASSWORD"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» make_token ACME\\\\Administrator S3cretPassw0rd\n" +
		"\t[-] Created job piloeJbKPp for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job piloeJbKPp for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+] Successfully created a Windows access token for ACME\\Administrator with a logon ID of 0xA703CF0"
	notes := "This command is an alias for the 'token make' command.\n" +
		"\tTokens are created with the Windows LogonUserW API call. " +
		"The token is created with a type 9 - NewCredentials logon type. " +
		"This is the equivalent of using runas.exe /netonly.\n" +
		"\tCommands such as 'token whoami' will show the username for the process and not the created token due to the " +
		"logon type, but will reflect the new Logon ID\n" +
		"\tWARNING: Type 9 - NewCredentials tokens only work for NETWORK authenticated activities\n" +
		"\tReferences:\n" +
		"\t\t- https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types"
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {
	if core.Debug {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Debug,
			Message: fmt.Sprintf("entering into Completer() for the '%s' command with Menu: %s, and id: %s", c, m, id),
			Time:    time.Now().UTC(),
		}
	}
	return readline.PcItem(c.name)
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	if core.Debug {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Debug,
			Message: fmt.Sprintf("entering into Do() for the '%s' command with Menu: %s, id: %s, and arguments: %s", c, m, id, arguments),
			Time:    time.Now().UTC(),
		}
	}

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	// 0. make_token, 1. -h
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}
	return token.NewCommand().Make(id, strings.Join(append([]string{"token", "make"}, args[1:]...), " "))
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	if core.Debug {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Debug,
			Message: fmt.Sprintf("entering into Help() for the '%s' command with Menu: %s", c, m),
			Time:    time.Now().UTC(),
		}
	}
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
