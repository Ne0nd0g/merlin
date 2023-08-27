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

package use

import (
	// Standard
	"fmt"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	// Internal
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	listenerEntity "github.com/Ne0nd0g/merlin/pkg/cli/entity/listener"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
	moduleMemory "github.com/Ne0nd0g/merlin/pkg/cli/module/memory"
	"github.com/Ne0nd0g/merlin/pkg/services/listeners"
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
	cmd.name = "use"
	cmd.menus = []menu.Menu{menu.LISTENERS, menu.MODULES}
	cmd.os = os.LOCAL
	description := "Select a protocol to create a listener for"
	usage := "use protocol"
	example := "Merlin[listeners]» use http3\n\tMerlin[listeners][http3]»"
	notes := "Use tab to cycle through available listener types"
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

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
		listenerService := listeners.NewListenerService()
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(listenerService.CLICompleter()),
		)
	case menu.MODULES:
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(moduleAPI.GetModuleListCompleter()),
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
		return c.DoListeners(arguments)
	case menu.MODULES:
		return c.DoModules(arguments)
	default:
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is not a valid menu for the '%s' command", m, c),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
	return
}

func (c *Command) DoListeners(arguments string) (response commands.Response) {
	description := "Select a protocol to create a listener for"
	example := "Merlin[listeners]» use http3\n\tMerlin[listeners][http3]»"
	notes := "Use tab to cycle through available listener types"
	usage := "use protocol"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

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

	// Get a list of all Listener types the server supports
	types := listenerAPI.GetListenerTypes()
	// Loop through the types and check if the user provided type is supported
	for _, t := range types {
		if strings.ToLower(t) == strings.ToLower(args[1]) {
			options, err := listenerAPI.GetDefaultOptions(t)
			if err != nil {
				response.Message = &messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("there was an getting default options for listener type '%s': %s", t, err),
					Time:    time.Now().UTC(),
					Error:   true,
				}
				return
			}
			// Build a new Listener structure
			l := listenerEntity.NewListener(t, options)
			// Add the Listener to the Listener repository
			repo := memory.NewRepository()
			repo.Add(l)
			// Build the Response
			response.Listener = l.ID()
			response.Menu = menu.LISTENERSETUP
			response.Prompt = fmt.Sprintf("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m%s\033[31m]»\033[0m ", t)
			return
		}
	}
	// If we get here, the user provided type is not supported
	response.Message = &messages.UserMessage{
		Level:   messages.Warn,
		Message: fmt.Sprintf("'%s' is not a supported listener type\n%s", args[1], c.help.Usage()),
		Time:    time.Now().UTC(),
	}

	return
}

func (c *Command) DoModules(arguments string) (response commands.Response) {
	description := "use & interact with a module"
	example := "Merlin[modules]» use windows/x64/powershell/powersploit/PowerUp\n" +
		"\tMerlin[modules][windows/x64/powershell/powersploit/PowerUp]»"
	notes := "Use tab to cycle through available modules"
	usage := "use module"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires one argument\n%s", c, h.Usage()),
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

	// Get the module options from the API based on the selected string
	// The module's absolute path is built on the server side
	message, m := moduleAPI.GetModule(args[1])
	if message.Error {
		response.Message = &message
		return
	}

	// Get the repository and store the module
	repo := moduleMemory.NewRepository()
	err := repo.Add(m)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Error:   true,
			Message: fmt.Sprintf("there was an error adding the %s module to the repository: %s", m, err),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Build the Response
	response.Module = m.ID()
	response.Menu = menu.MODULE
	response.Prompt = fmt.Sprintf("\033[31mMerlin[\033[32mmodules\033[31m][\033[33m%s\033[31m]»\033[0m ", args[1])
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
