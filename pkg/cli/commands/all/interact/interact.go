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

package interact

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
	"github.com/Ne0nd0g/merlin/pkg/cli/completer"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
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
	cmd.name = "interact"
	cmd.menus = []menu.Menu{menu.ALLMENUS}
	cmd.os = os.LOCAL
	cmd.help = make(map[menu.Menu]help.Help)

	// Help for all menus, or the default help
	description := "Interact with an agent or a listener"
	usage := "interact {agentID|listenerID}"
	example := "interact 0035409c-088f-45fc-9872-47aa1efab06b"
	notes := "The current menu determines what type of entity the command will interact with. " +
		"The default is to interact with Agents across all menus. " +
		"To interact with a Listener, use the 'listeners' menu.\n" +
		"Use tab completion to cycle through and select available Agents or Listeners."
	cmd.help[menu.ALLMENUS] = help.NewHelp(description, example, notes, usage)

	// Help for the Listener menu
	listenerDescription := "Interact with a Listener"
	listenerUsage := "interact listenerID"
	listenerExample := "Merlin» listeners \n" +
		"\tMerlin[listeners]» interact ae0c47c8-a1ca-4d65-9627-88843be8ddbc \n" +
		"\tMerlin[listeners][ae0c47c8-a1ca-4d65-9627-88843be8ddbc]»"
	listenerNotes := "Use tab completion to select an available listener"
	cmd.help[menu.LISTENERS] = help.NewHelp(listenerDescription, listenerExample, listenerNotes, listenerUsage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) (comp readline.PrefixCompleterInterface) {
	if core.Debug {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Debug,
			Message: fmt.Sprintf("entering into Completer() for the '%s' command with Menu: %s, and id: %s", c, m, id),
			Time:    time.Now().UTC(),
		}
	}
	switch m {
	case menu.LISTENERS:
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(completer.ListenerListCompleter()),
		)
	default:
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(completer.AgentListCompleter()),
		)
	}
	return
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

	switch m {
	case menu.LISTENERS:
		return c.DoListener(arguments)
	default:
		return c.DoAgent(arguments)
	}
}

func (c *Command) DoAgent(arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	h := c.help[menu.ALLMENUS]
	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires at least one argument\n%s", c, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}
	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}
	// Parse the UUID
	id, err := uuid.FromString(args[1])
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error parsing '%s' as a UUID: %s\nUsage: %s", args[1], err, h.Usage()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	// Request Agent information
	_, agentOS, err := agentAPI.GetAgent(id)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error retrieving Agent information: %s", err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		err = nil
		return
	}
	// Build the Response
	response.Agent = id
	response.AgentOS = os.FromString(agentOS)
	response.Menu = menu.AGENT
	response.Prompt = fmt.Sprintf("\033[31mMerlin[\033[32magent\033[31m][\033[33m%s\033[31m]»\033[0m ", id)
	return
}

func (c *Command) DoListener(arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	h := c.help[menu.LISTENERS]
	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires at least one argument\n%s", c, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}
	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}
	// Parse the UUID
	id, err := uuid.FromString(args[1])
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error parsing '%s' as a UUID: %s\nUsage: %s", args[1], err, h.Usage()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	// Build the Response
	response.Listener = id
	response.Menu = menu.LISTENER
	response.Prompt = fmt.Sprintf("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m%s\033[31m]»\033[0m ", id)
	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	switch m {
	case menu.LISTENERS:
		return c.help[m]
	default:
		return c.help[menu.ALLMENUS]
	}
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
