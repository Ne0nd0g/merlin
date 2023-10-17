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

package invoke_assembly

import (
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
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
	cmd.name = "invoke-assembly"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Execute a .NET assembly that was previously loaded into the agent with the 'load-assembly' command."
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "invoke-assembly assemblyName [assemblyArguments]"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly Rubeus.exe klist\n" +
		"\t[-] Created job GlPHKaRtmg for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[-] Results job GlPHKaRtmg for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n" +
		"\t   ______        _\n" +
		"\t  (_____ \\      | |\n" +
		"\t   _____) )_   _| |__  _____ _   _  ___\n" +
		"\t  |  __  /| | | |  _ \\| ___ | | | |/___)\n" +
		"\t  | |  \\ \\| |_| | |_) ) ____| |_| |___ |\n" +
		"\t  |_|   |_|____/|____/|_____)____/(___/\n\n" +
		"\t  v1.5.0\n\n\n" +
		"\tAction: List Kerberos Tickets (Current User)\n\n" +
		"\t[*] Current LUID    : 0x37913"
	notes := "Use the 'list-assemblies' command return a list of loaded assemblies. The execute-assembly " +
		"command is different because it uses injection to run the assembly in a child process. This command runs the " +
		"assembly in the current process without injection.\n\n" +
		"\tNote\n\n" +
		"\tOnly CLR v4 is currently supported which can be used to execute both v3.5 and v4 .NET assemblies"
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
	args, err := shellwords.Parse(arguments)
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing the arguments: %s", err))
		err = nil
		return
	}

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

	response.Message = rpc.InvokeAssembly(id, args[1:])
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
