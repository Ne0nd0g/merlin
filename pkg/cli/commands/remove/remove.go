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

package remove

import (
	"fmt"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
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
	cmd.name = "remove"
	cmd.menus = []menu.Menu{menu.MAIN}
	cmd.os = os.LOCAL
	cmd.help.Description = "Remove or delete an agent from the server so that it will not show up in the list of available agents."
	cmd.help.Usage = "remove <agent id>"
	cmd.help.Example = "Merlin» sessions\n\n" +
		"+--------------------------------------+-------------+------+--------+-----------------+--------+\n" +
		"|              AGENT GUID              |  PLATFORM   | USER |  HOST  |    TRANSPORT    | STATUS |\n" +
		"+--------------------------------------+-------------+------+--------+-----------------+--------+\n" +
		"| c62ac059-e54d-4204-82a4-d5c054b63ac3 | linux/amd64 | joe  | DEV001 | HTTP/2 over TLS |  Dead  |\n" +
		"+--------------------------------------+-------------+------+--------+-----------------+--------+\n\n" +
		"Merlin» remove c62ac059-e54d-4204-82a4-d5c054b63ac3\n" +
		"Merlin»\n" +
		"[i] Agent c62ac059-e54d-4204-82a4-d5c054b63ac3 was removed from the server\n" +
		"Merlin» sessions\n\n" +
		"+------------+----------+------+------+-----------+--------+\n" +
		"| AGENT GUID | PLATFORM | USER | HOST | TRANSPORT | STATUS |\n" +
		"+------------+----------+------+------+-----------+--------+\n" +
		"+------------+----------+------+------+-----------+--------+"
	cmd.help.Notes = "Use tab completion to cycle through available agents"
	return &cmd
}

func (c *Command) Completer(id uuid.UUID) (readline.PrefixCompleterInterface, error) {
	return readline.PcItem(c.name,
		readline.PcItemDynamic(agentListCompleter()),
	), nil
}

func (c *Command) Description() string {
	return c.help.Description
}

func (c *Command) Do(arguments string) (message messages.UserMessage) {
	// Parse the arguments
	args := strings.Split(arguments, " ")
	if len(args) == 1 {
		message.Message = c.Usage()
		message.Level = messages.Info
		message.Time = time.Now().UTC()
		return
	}

	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
			message.Level = messages.Info
			message.Time = time.Now().UTC()
			return
		}
		// Convert the first argument to a UUID
		id, err := uuid.FromString(args[1])
		if err != nil {
			message.Message = fmt.Sprintf("there was an error converting '%s' to an Agent ID: %s", args[1], err)
			message.Level = messages.Warn
			message.Time = time.Now().UTC()
			message.Error = true
			return
		}
		// Remove the agent
		message = agentAPI.Remove(id)
	}
	return
}

func (c *Command) DoID(id uuid.UUID, arguments string) (message messages.UserMessage) {
	return c.Do(arguments)
}

func (c *Command) Menu(m menu.Menu) bool {
	for _, v := range c.menus {
		if v == m || v == menu.ALLMENUS {
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

// agentListCompleter returns a list of agents that exist and is used for command line tab completion
func agentListCompleter() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		agentList := agentAPI.GetAgents()
		for _, id := range agentList {
			a = append(a, id.String())
		}
		return a
	}
}
