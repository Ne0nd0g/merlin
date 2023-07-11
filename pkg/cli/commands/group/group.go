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

package group

import (
	"fmt"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"
	os2 "os"
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
	cmd.name = "group"
	cmd.menus = []menu.Menu{menu.ALLMENUS}
	cmd.os = os.LOCAL
	cmd.help.Description = "Add, list, or remove Agent groupings"
	cmd.help.Usage = "group [add | list | remove ] <group>"
	cmd.help.Example = ""
	cmd.help.Notes = "The 'all' group uses the broadcast UUID of  ffffffff-ffff-ffff-ffff-ffffffffffff"
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
		case "add":
			if len(args) >= 3 {
				switch strings.ToLower(args[2]) {
				case "help", "-h", "--help", "/?":
					message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
					message.Level = messages.Info
					message.Time = time.Now().UTC()
					return
				}
			}
			if len(args) < 4 {
				message.Message = "Invalid number of arguments\ngroup add <agent> <group>"
				message.Level = messages.Warn
				message.Time = time.Now().UTC()
				message.Error = true
				return
			}

			id, err := uuid.FromString(args[2])
			if err != nil {
				return messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("Invalid UUID: %s", args[2]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				return agentAPI.GroupAdd(id, args[3])
			}

		case "list":
			if len(args) >= 3 {
				switch strings.ToLower(args[2]) {
				case "help", "-h", "--help", "/?":
					message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
					message.Level = messages.Info
					message.Time = time.Now().UTC()
					return
				}
			}
			var data [][]string
			if len(args) >= 3 {
				agents := agentAPI.GroupList(args[2])
				for _, a := range agents {
					data = append(data, []string{args[2], a})
				}
			} else {
				data = agentAPI.GroupListAll()
			}

			table := tablewriter.NewWriter(os2.Stdout)
			table.SetHeader([]string{"Group", "Agent ID"})
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(false)
			table.SetBorder(true)
			table.AppendBulk(data)
			table.Render()
			return
		case "remove":
			if len(args) >= 3 {
				switch strings.ToLower(args[2]) {
				case "help", "-h", "--help", "/?":
					message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
					message.Level = messages.Info
					message.Time = time.Now().UTC()
					return
				}
			}
			if len(args) < 4 {
				return messages.UserMessage{
					Level:   messages.Warn,
					Message: "Invalid number of arguments\n group remove <agent> <group>",
					Time:    time.Now().UTC(),
					Error:   true,
				}
			}
			id, err := uuid.FromString(args[2])
			if err != nil {
				return messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("Invalid UUID: %s", args[2]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			}
			return agentAPI.GroupRemove(id, args[3])
		default:
			message.Message = c.Usage()
			message.Level = messages.Info
			message.Time = time.Now().UTC()
		}
	}
	return
}

func (c *Command) DoID(agent uuid.UUID, arguments string) (message messages.UserMessage) {
	return c.Do(arguments)
}

func (c *Command) Menu(m menu.Menu) bool {
	// Menu is ALLMENUS so return true
	return true
}

func (c *Command) String() string {
	return c.name
}

func (c *Command) Usage() string {
	return c.help.Usage
}
