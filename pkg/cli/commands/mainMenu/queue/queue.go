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

package queue

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
	cmd.name = "queue"
	cmd.menus = []menu.Menu{menu.MAIN}
	cmd.os = os.LOCAL
	description := "Queue up commands for one, multiple, unknown agents, or a group"
	usage := "queue {agentID|groupName} command [args]"
	example := "Queue a command for one agent:\n\n" +
		"\tMerlin» queue 99dbe632-984c-4c98-8f38-11535cb5d937 run ping 8.8.8.8\n" +
		"\t[-] Created job LumWveIkKe for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n" +
		"\t[-] Results job LumWveIkKe for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n\n" +
		"\t[+]\n\tPinging 8.8.8.8 with 32 bytes of data:\n" +
		"\tReply from 8.8.8.8: bytes=32 time=42ms TTL=128\n" +
		"\tReply from 8.8.8.8: bytes=32 time=63ms TTL=128\n" +
		"\tReply from 8.8.8.8: bytes=32 time=35ms TTL=128\n" +
		"\tReply from 8.8.8.8: bytes=32 time=48ms TTL=128\n\n" +
		"\tPing statistics for 8.8.8.8:\n" +
		"\tPackets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n" +
		"\tApproximate round trip times in milli-seconds:\n" +
		"\tMinimum = 35ms, Maximum = 63ms, Average = 47ms\n\n" +
		"\tQueue a command for a group:\n\n" +
		"\tMerlin» queue EvilCorp run whoami\n\n" +
		"\t[-] Created job lkvozuKJLW for agent d07edfda-e119-4be2-a20f-918ab701fa3c\n" +
		"\t[-] Created job xKAgunnKTF for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n" +
		"\t[-] Results job xKAgunnKTF for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n\n" +
		"\t[+] DESKTOP-H39FR21\\bob\n\n" +
		"\t[-] Results job lkvozuKJLW for agent d07edfda-e119-4be2-a20f-918ab701fa3c\n\n" +
		"\t[+] rastley\n\n" +
		"\tQueue a command for an unknown agent:\n\n" +
		"\tMerlin» queue c1090dbc-f2f7-4d90-a241-86e0c0217786 run whoami\n" +
		"\t[-] Created job rJVyZTuHkm for agent c1090dbc-f2f7-4d90-a241-86e0c0217786"
	notes := "Some agent control commands such as 'sleep' can not be queued because the agent structure must exist on the server to calculate the JWT"
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {
	return readline.PcItem(c.name,
		readline.PcItemDynamic(completer.AgentListCompleter()),
		readline.PcItemDynamic(completer.GroupListCompleter()),
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

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		}
	}
	// Check for the correct number of arguments
	// 0. queue, 1. AgentID/Group, 2. command, 3. [args]
	if len(args) < 3 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least two arguments\n%s", c.name, c.help.Usage()))
		return
	}

	// THE ACTUAL LOGIC FOR THIS COMMAND IS IN THE CLI SERVICE

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
