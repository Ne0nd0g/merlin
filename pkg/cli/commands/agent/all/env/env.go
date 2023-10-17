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

package env

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
	cmd.name = "env"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "View or modify operating system environment variables"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "env {get|set|showall|unset} [variable] [value]"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env get TEST1\n" +
		"\t[-] Created job xaSqAdQBXs for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job xaSqAdQBXs for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n\tEnvironment variable TEST1=TESTINGTEST\n"
	notes := "Uses Go native libraries and does not call operating system programs. Use '-h' after the sub command for more information."
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {
	return readline.PcItem(c.name,
		readline.PcItem("get"),
		readline.PcItem("set"),
		readline.PcItem("showall"),
		readline.PcItem("unset"),
	)
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

	switch strings.ToLower(args[1]) {
	case "get":
		return c.Get(id, arguments)
	case "set":
		return c.Set(id, arguments)
	case "showall":
		return c.Show(id, arguments)
	case "unset":
		return c.Unset(id, arguments)
	case "help", "-h", "--help", "?", "/?":
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
		return
	default:
		response.Message = message.NewUserMessage(message.Info, c.help.Usage())
		return
	}
}

func (c *Command) Get(id uuid.UUID, arguments string) (response commands.Response) {
	description := "Retrieve the value of an existing environment variable."
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env get TEST1\n" +
		"\t[-] Created job xaSqAdQBXs for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job xaSqAdQBXs for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n\tEnvironment variable TEST1=TESTINGTEST\n"
	notes := ""
	usage := "env get variable"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")
	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 3 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s get' command requires at least one argument\n%s", c, c.help.Usage()))
		return
	}
	// Check for help first
	// 0. env, 1. get, 2. help
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s get' command help\n\ndescription :=\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}
	response.Message = rpc.ENV(id, args[1:])
	return
}

func (c *Command) Set(id uuid.UUID, arguments string) (response commands.Response) {
	description := "Create or modify an environment variable with the specified value"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env set TEST1 TESTINGTEST\n" +
		"\t[-] Created job NcyukONetb for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job NcyukONetb for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n\tSet environment variable: TEST1=TESTINGTEST"
	notes := ""
	usage := "env set variable value"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	// 0. env, 1. set, 2. help
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s set' command help\n\ndescription :=\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// Validate at least one argument, in addition to the command, was provided
	// 0. env, 1. set, 2. variable, 3. value
	if len(args) < 4 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s set' command requires two arguments\n%s", c, h.Usage()))
		return
	}
	response.Message = rpc.ENV(id, args[1:])
	return
}

func (c *Command) Show(id uuid.UUID, arguments string) (response commands.Response) {
	description := "Enumerate and return all environment variables and their value"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env showall\n" +
		"\t[-] Created job NzbQEytJpY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job NzbQEytJpY for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n" +
		"\tEnvironment variables:\n" +
		"\tSHELL=/bin/bash\n" +
		"\tSESSION_MANAGER=local/ubuntu:@/tmp/.ICE-unix/3195,unix/ubuntu:/tmp/.ICE-unix/3195\n" +
		"\tQT_ACCESSIBILITY=1\n" +
		"\tSNAP_REVISION=148\n" +
		"\tXDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg\n" +
		"\tXDG_MENU_PREFIX=gnome-\n\tGNOME_DESKTOP_SESSION_ID=this-is-deprecated\n" +
		"\tSNAP_REAL_HOME=/home/rastley\n" +
		"\tGNOME_SHELL_SESSION_MODE=ubuntu\n" +
		"\tSSH_AUTH_SOCK=/run/user/1000/keyring/ssh"
	notes := ""
	usage := "env showall"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	// 0. env, 1. showall, 2. help
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s showall' command help\n\ndescription :=\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}
	response.Message = rpc.ENV(id, args[1:])
	return
}

func (c *Command) Unset(id uuid.UUID, arguments string) (response commands.Response) {
	description := "Clear, or empty, the environment variable name provided"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env unset TEST1\n" +
		"\t[-] Created job hEYjNYeniT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job hEYjNYeniT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n" +
		"\tUnset environment variable: TEST1\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env get TEST1\n" +
		"\t[-] Created job IhKdCrKHEr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job IhKdCrKHEr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+]\n" +
		"\tEnvironment variable TEST1="
	notes := ""
	usage := "env unset variable"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Validate at least one argument, in addition to the command, was provided
	// 0. env, 1. unset, 2. variable || help
	if len(args) < 3 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s set' command requires one argument\n%s", c, h.Usage()))
		return
	}
	// Check for help first
	switch strings.ToLower(args[2]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s unset' command help\n\ndescription :=\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
		return
	}
	response.Message = rpc.ENV(id, args[1:])
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
