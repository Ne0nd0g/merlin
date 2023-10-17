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
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/completer"
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
	cmd.name = "group"
	cmd.menus = []menu.Menu{menu.MAIN}
	cmd.os = os.LOCAL
	description := "Add, list, or remove Agent groupings"
	usage := "group {add agentID groupName | list [groupName] |remove agentID groupName}"
	example := ""
	notes := "The 'all' group uses the broadcast UUID of  ffffffff-ffff-ffff-ffff-ffffffffffff.\n" +
		"\tUse 'group add -h' syntax for sub command help." +
		"\tUse tab completion to list available groups and agents."
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {
	comp := readline.PcItem("group",
		readline.PcItem("list",
			readline.PcItemDynamic(completer.GroupListCompleter()),
		),
		readline.PcItem("add",
			readline.PcItemDynamic(completer.AgentListCompleter(),
				readline.PcItemDynamic(completer.GroupListCompleter()),
			),
		),
		readline.PcItem("remove",
			readline.PcItemDynamic(completer.AgentListCompleter(),
				readline.PcItemDynamic(completer.GroupListCompleter()),
			),
		),
	)
	return comp
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		case "add":
			return c.Add(id, arguments)
		case "list":
			return c.List(arguments)
		case "remove":
			return c.Remove(id, arguments)
		}
	}
	response.Message = message.NewUserMessage(message.Info, c.help.Usage())
	return
}

// Add adds an agent to a named group and creates the group if it does not exist
func (c *Command) Add(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "add"

	description := "Add an agent to a named group"
	example := "Merlin» group add 99dbe632-984c-4c98-8f38-11535cb5d937 EvilCorp\n" +
		"\t[i] Agent 99dbe632-984c-4c98-8f38-11535cb5d937 added to group EvilCorp\n\n" +
		"\tMerlin» group add d07edfda-e119-4be2-a20f-918ab701fa3c EvilCorp\n" +
		"\t[i] Agent d07edfda-e119-4be2-a20f-918ab701fa3c added to group EvilCorp"
	notes := "If the group name does not exist, it will be created. The list of available agents can be tab completed."
	usage := "group add agentID groupName"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command help\nDescription:\n\t%s\n\nUsage:\n\t%s\n\nExample:\n\t%s\n\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// Validate at least one argument, in addition to the command, was provided
	// 0. group, 1. add, 2. agent, 3. group
	if len(args) < 4 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command requires two arguments\n%s", c, sub, h.Usage()))
		return
	}

	// Group name can't be "all" because it is reserved
	if strings.ToLower(args[3]) == "all" {
		response.Message = message.NewUserMessage(message.Warn, "'all' is a reserved group name and cannot be used")
		return
	}

	var err error
	id, err = uuid.FromString(args[2])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing the agent ID '%s': %s\n%s", args[2], err, h.Usage()))
		return
	}

	response.Message = rpc.GroupAdd(id, args[3])
	return
}

// List lists all agents in a named group or all groups if no group name is provided
func (c *Command) List(arguments string) (response commands.Response) {
	description := "Show all existing group names"
	example := "Merlin» group list\n" +
		"\t+----------+--------------------------------------+\n" +
		"\t|  GROUP   |               AGENT ID               |\n" +
		"\t+----------+--------------------------------------+\n" +
		"\t| all      | ffffffff-ffff-ffff-ffff-ffffffffffff |\n" +
		"\t| EvilCorp | 99dbe632-984c-4c98-8f38-11535cb5d937 |\n" +
		"\t| EvilCorp | d07edfda-e119-4be2-a20f-918ab701fa3c |\n" +
		"\t+----------+--------------------------------------+"
	notes := "Includes agents that are members of a group. The 'all' group always exists and is used to task every known agent."
	usage := "group list"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s list' command help\nDescription:\n\t%s\n\nUsage:\n\t%s\n\nExample:\n\t%s\n\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}
	var data [][]string
	if len(args) >= 3 {
		agents := rpc.GroupList(args[2])
		for _, a := range agents {
			data = append(data, []string{args[2], a})
		}
	} else {
		groups := rpc.GroupListAll()
		for g, m := range groups {
			data = append(data, []string{g, strings.Join(m, " ")})
		}
	}

	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Group", "Agent ID"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowLine(false)
	table.SetBorder(true)
	table.AppendBulk(data)
	table.Render()

	response.Message = message.NewUserMessage(message.Plain, fmt.Sprintf("\n%s", tableString.String()))
	return
}

// Remove removes an agent from a named group
func (c *Command) Remove(id uuid.UUID, arguments string) (response commands.Response) {
	description := "Remove an agent to a named group"
	example := "Merlin» group remove 99dbe632-984c-4c98-8f38-11535cb5d937 EvilCorp\n" +
		"\t[i] Agent 99dbe632-984c-4c98-8f38-11535cb5d937 removed from group EvilCorp"
	notes := "The list of ALL agents is tab completable but does not mean the agent is in the group. " +
		"The list of existing groups can also be tab completed."
	usage := "group remove agentID groupName"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s remove' command help\nDescription:\n\t%s\n\nUsage:\n\t%s\n\nExample:\n\t%s\n\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// Validate at least one argument, in addition to the command, was provided
	// 0. group, 1. remove, 2. <agent>, 3. <group>
	if len(args) < 4 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s remove' command requires two arguments\n%s", c, h.Usage()))
		return
	}

	// Group name can't be "all" because it is reserved
	if strings.ToLower(args[3]) == "all" {
		response.Message = message.NewUserMessage(message.Warn, "'all' is a reserved group name and cannot be used")
		return
	}

	var err error
	id, err = uuid.FromString(args[2])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing the agent ID '%s': %s\n%s", args[2], err, h.Usage()))
		return
	}

	response.Message = rpc.GroupRemove(id, args[3])
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
