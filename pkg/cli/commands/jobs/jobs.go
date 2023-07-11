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

package jobs

import (
	"fmt"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	os2 "github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"
	"os"
	"strings"
	"time"
)

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string      // name is the name of the command
	help   help.Help   // help is the Help structure for the command
	menus  []menu.Menu // menu is the Menu the command can be used in
	native bool        // native is true if the command is executed by an Agent using only Golang native code
	os     os2.OS      // os is the supported operating system the Agent command can be executed on
}

func NewCommand() *Command {
	var cmd Command
	cmd.name = "jobs"
	cmd.menus = []menu.Menu{menu.AGENT, menu.MAIN}
	cmd.os = os2.LOCAL
	cmd.help.Description = "Display all unfinished jobs"
	cmd.help.Usage = "jobs"
	cmd.help.Example = "Merlin» jobs\n\n" +
		"AGENT                 |     ID     |  COMMAND   | STATUS  |       CREATED        |         SENT\n" +
		"+--------------------------------------+------------+------------+---------+----------------------+----------------------+\n" +
		"  d07edfda-e119-4be2-a20f-918ab701fa3c | UjNoTALgcn | pwd        | Created | 2021-08-03T01:39:57Z |\n" +
		"  99dbe632-984c-4c98-8f38-11535cb5d937 | UHOddpFQTm | run whoami | Sent    | 2021-08-03T01:40:11Z | 2021-08-03T01:40:17Z"
	cmd.help.Notes = ""
	return &cmd
}

func (c *Command) Completer(id uuid.UUID) (readline.PrefixCompleterInterface, error) {
	return readline.PcItem(c.name), nil
}

func (c *Command) Description() string {
	return c.help.Description
}

func (c *Command) Do(arguments string) (message messages.UserMessage) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
			message.Level = messages.Info
			message.Time = time.Now().UTC()
			return
		default:
			message.Message = c.Usage()
			message.Level = messages.Info
			message.Time = time.Now().UTC()
			return
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"Agent", "ID", "Command", "Status", "Created", "Sent"})

	table.AppendBulk(agentAPI.GetJobs())
	fmt.Println()
	table.Render()
	fmt.Println()

	return
}

func (c *Command) DoID(agent uuid.UUID, arguments string) (message messages.UserMessage) {
	return c.Do(arguments)
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
