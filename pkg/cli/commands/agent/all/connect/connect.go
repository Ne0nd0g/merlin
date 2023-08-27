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

package connect

import (
	// Standard
	"fmt"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
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
	cmd.name = "connect"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Instruct an Agent to re-connect it's primary communicate channel to the provide address"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "connect uri"
	example := "HTTP Agent:\n\n" +
		"\tMerlin[agent][b3c03f46-b327-45c1-ac82-71a49032d4ad]» connect https://192.168.22.100/NeverGonnaGiveYouUp\n" +
		"\t[-] Created job QZnUPPEooZ for agent b3c03f46-b327-45c1-ac82-71a49032d4ad at 2023-08-03T11:04:08Z\n" +
		"\t[-] Results of job QZnUPPEooZ for agent b3c03f46-b327-45c1-ac82-71a49032d4ad at 2023-08-03T11:04:24Z\n" +
		"\t        Configuration data received for Agent b3c03f46-b327-45c1-ac82-71a49032d4ad and updated. Issue the \"info\" command to view it.\n\n" +
		"\tTCP bind Agent:\n\n" +
		"\tMerlin[agent][13f6ebee-78ec-4414-a04c-74188b95c01c]» connect 192.168.31.163:4444\n" +
		"\t[-] Created job IFDLuKIRHD for agent 13f6ebee-78ec-4414-a04c-74188b95c01c at 2023-08-03T11:09:36Z\n" +
		"\tMerlin[agent][13f6ebee-78ec-4414-a04c-74188b95c01c]» interact b3c03f46-b327-45c1-ac82-71a49032d4ad \n" +
		"\tMerlin[agent][b3c03f46-b327-45c1-ac82-71a49032d4ad]» link tcp 192.168.31.163:4444\n" +
		"\t[-] Created job QeoGIbKQjh for agent b3c03f46-b327-45c1-ac82-71a49032d4ad at 2023-08-03T11:10:43Z\n" +
		"\t[-] Results of job QeoGIbKQjh for agent b3c03f46-b327-45c1-ac82-71a49032d4ad at 2023-08-03T11:11:04Z\n\n" +
		"\t[+] Successfully connected to tcp-bind Agent 13f6ebee-78ec-4414-a04c-74188b95c01c at 192.168.31.163:4444\n" +
		"\t[-] Results of job IFDLuKIRHD for agent 13f6ebee-78ec-4414-a04c-74188b95c01c at 2023-08-03T11:11:04Z\n" +
		"\t        Configuration data received for Agent 13f6ebee-78ec-4414-a04c-74188b95c01c and updated. Issue the \"info\" command to view it.\n"
	notes := "HTTP based Agents use a URI like https://127.0.0.1\n" +
		"\tTCP/UDP Agents use a URI like 127.0.0.1:7777\n" +
		"\tSMB Beacons use a URI like \\\\\\\\127.0.0.1\\\\pipe\\\\merlinpipe and the backslashes need to be escaped.\n" +
		"\tBind Agents will listen on the new interface and reverse Agents will connect to the new uri.\n\n" +
		"\tIf you get the jobs results back, the Agent has successfully reconnected."
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
	// These are the default values for the Agent
	return readline.PcItem(c.name,
		readline.PcItem("https://127.0.0.1"),
		readline.PcItem("127.0.0.1:7777"),
		readline.PcItem("\\\\\\\\127.0.0.1\\\\pipe\\\\merlinpipe"),
	)
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

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()),
			Time:    time.Now().UTC(),
		}
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
	msg := agentAPI.Connect(id, args)
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
