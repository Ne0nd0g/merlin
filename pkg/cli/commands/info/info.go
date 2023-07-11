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

package info

import (
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
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
	cmd.name = "info"
	cmd.menus = []menu.Menu{menu.LISTENERSETUP}
	cmd.os = os.LOCAL
	cmd.help.Description = "Display the Listener template configurable options and their current value."
	cmd.help.Usage = "info"
	cmd.help.Example = "Merlin[listeners]» use https\n" +
		"Merlin[listeners][https]» info\n" +
		"+-------------+------------------+\n" +
		"|    NAME     |      VALUE       |\n" +
		"+-------------+------------------+\n" +
		"| PSK         | merlin           |\n" +
		"+-------------+------------------+\n" +
		"| Interface   | 127.0.0.1        |\n" +
		"+-------------+------------------+\n" +
		"| Port        | 443              |\n" +
		"+-------------+------------------+\n" +
		"| URLS        | /                |\n" +
		"+-------------+------------------+\n" +
		"| X509Cert    |                  |\n" +
		"+-------------+------------------+\n" +
		"| X509Key     |                  |\n" +
		"+-------------+------------------+\n" +
		"| Name        | Default          |\n" +
		"+-------------+------------------+\n" +
		"| Description | Default listener |\n" +
		"+-------------+------------------+\n" +
		"| Protocol    | https            |\n" +
		"+-------------+------------------+\n" +
		"Merlin[listeners][https]»"
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
		}
	}

	return
}

func (c *Command) DoID(id uuid.UUID, arguments string) (message messages.UserMessage) {
	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		message.Message = fmt.Sprintf("there was an error getting the listener for ID %s: %s", id, err)
		message.Level = messages.Warn
		message.Time = time.Now().UTC()
		return
	}

	// Set up the table
	table := tablewriter.NewWriter(os2.Stdout)
	table.SetHeader([]string{"Name", "Value"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowLine(true)
	table.SetBorder(true)

	for k, v := range listener.Options() {
		table.Append([]string{k, v})
	}
	// TODO lock STDOUT
	table.Render()
	return messages.UserMessage{}
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
