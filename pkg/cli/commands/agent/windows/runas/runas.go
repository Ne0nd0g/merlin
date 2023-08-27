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

package runas

import (
	// Standard
	"fmt"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
	uuid "github.com/satori/go.uuid"

	// Internal
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
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
	cmd.name = "runas"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Run a program as a different user."
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "runas domain\\user password program [arguments]"
	example := "Merlin[agent][336154be-9ab9-4add-96e6-69c79f1ce77d]» " +
		"runas ACME\\\\Administrator S3cretPassw0rd cmd.exe /c dir \\\\\\\\DC01.ACME.COM\\\\C$\n" +
		"\t[-] Created job PABQYrMLYO for agent 336154be-9ab9-4add-96e6-69c79f1ce77d\n" +
		"\t[-] Results job PABQYrMLYO for agent 336154be-9ab9-4add-96e6-69c79f1ce77d\n" +
		"\t[+] Created cmd.exe process with PID 2120"
	notes := "This command uses the CreateProcessWithLogonW Windows API call\n" +
		"\tReferences:\n" +
		"\t\t- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw"
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
	args, err := shellwords.Parse(arguments)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Error:   true,
			Message: fmt.Sprintf("there was an error parsing the arguments: %s", err),
			Time:    time.Now().UTC(),
		}
		err = nil
		return
	}

	// Check for help first
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
	// 0. runas, 1. domain\user, 2. password, 3. program, 4. arguments
	if len(args) < 4 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires at least 3 arguments:\n%s", c, c.help.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}
	msg := agentAPI.RunAs(id, args)
	response.Message = &msg
	return
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
