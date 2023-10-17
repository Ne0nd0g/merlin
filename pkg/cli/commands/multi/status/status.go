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

package status

import (
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
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
	name   string                  // name is the name of the command
	help   map[menu.Menu]help.Help // help is the Help structure for the command
	menus  []menu.Menu             // menu is the Menu the command can be used in
	native bool                    // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS                   // os is the supported operating system the Agent command can be executed on
}

// NewCommand is a factory that builds and returns a Command structure that implements the Command interface
func NewCommand() *Command {
	var cmd Command
	cmd.name = "status"
	cmd.menus = []menu.Menu{menu.AGENT, menu.LISTENER}
	cmd.os = os.LOCAL
	cmd.help = make(map[menu.Menu]help.Help)

	// Help for the Agent menu
	agentDescription := "Display if the Agent is active, delayed, or dead"
	// Style guide for usage https://developers.google.com/style/code-syntax
	agentUsage := "status"
	agentExample := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» status\n" +
		"\tc1090dbc-f2f7-4d90-a241-86e0c0217786 agent is active"
	agentNotes := "The Agent's status is determined by it's sleep time * maxretry count. The Agent is active if it " +
		"has checked in with the duration of one sleep interval. The Agent is delayed if it hasn't checked in after one" +
		" sleep interval but hasn't reached the maxretry count. The Agent is dead if it hasn't checked in after the " +
		"maxretry count. The status is calculated server-side and therefore the Agent could be alive but paused."
	cmd.help[menu.AGENT] = help.NewHelp(agentDescription, agentExample, agentNotes, agentUsage)

	// Help for the Listener menu
	listenerDescription := "Display the listener's status"
	listenerExample := "Merlin[listeners][1252dd69-e5d5-4023-b1d0-84813f6c1750]» status \n" +
		"\t[i] 1252dd69-e5d5-4023-b1d0-84813f6c1750 listener is Running"
	listenerNotes := ""
	listenerUsage := "status"
	cmd.help[menu.LISTENER] = help.NewHelp(listenerDescription, listenerExample, listenerNotes, listenerUsage)

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
	switch m {
	case menu.AGENT:
		return c.DoAgent(id, arguments)
	case menu.LISTENER:
		return c.DoListener(id, arguments)
	}
	return
}

func (c *Command) DoAgent(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		h := c.help[menu.AGENT]
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	a, err := rpc.GetAgent(id)
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("pkg/cli/commands/status.Do(): %s", err))
		return
	}

	if a.Status() == "Active" {
		response.Message = message.NewUserMessage(message.Plain, color.GreenString("%s agent is active\n", id))
	} else if a.Status() == "Delayed" {
		response.Message = message.NewUserMessage(message.Plain, color.YellowString("%s agent is delayed\n", id))
	} else if a.Status() == "Dead" {
		response.Message = message.NewUserMessage(message.Plain, color.RedString("%s agent is dead\n", id))
	} else {
		response.Message = message.NewUserMessage(message.Plain, color.BlueString("%s agent is %s\n", id, a.Status()))
	}
	return
}

func (c *Command) DoListener(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		h := c.help[menu.LISTENER]
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	response.Message = rpc.ListenerStatus(id)
	if response.Message.Error() {
		return
	}

	response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("%s listener is %s", id, response.Message.Message()))
	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	h, ok := c.help[m]
	if !ok {
		return help.NewHelp(fmt.Sprintf("the 'status' command's Help structure does not exist for the %s menu", m), "", "", "")
	}
	return h
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
