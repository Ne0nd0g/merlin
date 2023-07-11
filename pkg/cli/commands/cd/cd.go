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

package cd

import (
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"
	"strings"
	"time"
)

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string      // name is the name of the command
	help   help.Help   // help is the Help structure for the command
	menus  []menu.Menu // menu is the Menu the command can be used in
	native bool        // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS       // os is the supported operating system the Agent command can be executed on
}

func NewCommand() *Command {
	var cmd Command
	cmd.name = "cd"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	cmd.help.Description = "Change the Agent's current working directory to provided file system path"
	cmd.help.Usage = "cd <path>"
	cmd.help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» cd /usr/bin\n[-]Created job evtawDqBWa for agent " +
		"a98e6175-7799-47fb-abf0-32534a9191f0 at 2019-02-27T01:03:57Z\nMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»" +
		"\n[+]Results for job evtawDqBWa at 2019-02-27T01:03:59Z\nChanged working directory to /usr/bin"
	cmd.help.Example += "\n\nMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» cd /usr/bin\n" +
		"[-]Created job evtawDqBWa for agent a98e6175-7799-47fb-abf0-32534a9191f0 at 2019-02-27T01:03:57Z\n" +
		"Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job evtawDqBWa at 2019-02-27T01:03:59Z\n" +
		"Changed working directory to /usr/bin"
	cmd.help.Notes = "Relative paths can be used (e.g.,. ./../ or downloads\\\\Merlin). " +
		"This command uses native Go and will not execute the cd binary program found on the host operating system.\n" +
		"The \\ in a Windows directory must be escaped like C:\\\\Windows\\\\System32.\n"
	return &cmd
}

func (c *Command) Completer(id uuid.UUID) (readline.PrefixCompleterInterface, error) {
	return readline.PcItem(c.name), nil
}

func (c *Command) Description() string {
	return c.help.Description
}

func (c *Command) Do(arguments string) (message messages.UserMessage) {
	message = messages.ErrorMessage("this command can only be executed from the Agent menu")
	return
}

func (c *Command) DoID(agent uuid.UUID, arguments string) (message messages.UserMessage) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Validate the arguments
	// 0. "cd"
	// 1. <path> || help
	if len(args) < 2 {
		message = messages.ErrorMessage(fmt.Sprintf("invalid number of arguments for the 'cd' command\n%s", c.help.Usage))
		return
	}

	// Do
	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "/?":
		message.Message = fmt.Sprintf("%s\n%s\n\n%s\n\n%s", c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
		message.Level = 1
		message.Time = time.Now().UTC()
	default:
		message = agents.CD(agent, args[1:])
	}
	return
}

func (c *Command) Menu(m menu.Menu) bool {
	for _, v := range c.menus {
		if v == m {
			return true
		}
	}
	return false
}

func (c *Command) String() string {
	return c.name
}

func (c *Command) Usage() string {
	return c.help.Usage
}
