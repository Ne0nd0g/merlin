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

package set

import (
	// Standard
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	// Internal
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/completer"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
	moduleMemory "github.com/Ne0nd0g/merlin/pkg/cli/module/memory"
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
	cmd.name = "set"
	cmd.menus = []menu.Menu{menu.LISTENER, menu.LISTENERSETUP, menu.MODULE}
	cmd.os = os.LOCAL
	cmd.help = make(map[menu.Menu]help.Help)

	// Help for the Listener menu
	listenerDescription := "Set a configurable option"
	listenerUsage := "set option value"
	listenerExample := ""
	listenerNotes := "Use tab completion to cycle through configurable options."
	cmd.help[menu.LISTENER] = help.NewHelp(listenerDescription, listenerExample, listenerNotes, listenerUsage)

	// Help for Listener Setup menu
	listenerSetupDescription := "Set a configurable option"
	listenerSetupUsage := "set option value"
	listenerSetupExample := "Merlin[listeners]» use https\n" +
		"\tMerlin[listeners][https]» set Name Merlin Demo Listener\n" +
		"\t[+] set Name to: Merlin Demo Listener\n" +
		"\tMerlin[listeners][https]»"
	listenerSetupNotes := "Use tab completion to cycle through configurable options."
	cmd.help[menu.LISTENERSETUP] = help.NewHelp(listenerSetupDescription, listenerSetupExample, listenerSetupNotes, listenerSetupUsage)

	// Help for the Module menu
	moduleDescription := "set the value of a configurable module option"
	moduleExample := "Merlin[modules][linux/x64/bash/exec/bash]» set Agent 1ca5e186-fadd-4b19-94ba-065ffaef9dfe \n" +
		"\t[+] agent set to 1ca5e186-fadd-4b19-94ba-065ffaef9dfe\n" +
		"\tMerlin[modules][linux/x64/bash/exec/bash]» set Command hostname\n" +
		"\t[+] Command set to hostname\n" +
		"\tMerlin[modules][linux/x64/bash/exec/bash]» show\n" +
		"\t[i] \n" +
		"\t'BASH' module options\n\n" +
		"\t\t   NAME   |                VALUE                 | REQUIRED |          DESCRIPTION            \n" +
		"\t\t+---------+--------------------------------------+----------+--------------------------------+\n" +
		"\t\t  Agent   | 1ca5e186-fadd-4b19-94ba-065ffaef9dfe | true     | Agent on which to run module    \n" +
		"\t\t          |                                      |          | BASH                            \n" +
		"\t\t  Command | hostname                             | true     | Command to run in BASH          \n" +
		"\t\t          |                                      |          | terminal                        \n"
	moduleNotes := "Use tab completion to cycle through configurable options."
	moduleUsage := "set key value"
	cmd.help[menu.MODULE] = help.NewHelp(moduleDescription, moduleExample, moduleNotes, moduleUsage)

	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) (comp readline.PrefixCompleterInterface) {
	var options map[string]string
	switch m {
	case menu.LISTENER:
		var msg messages.UserMessage
		msg, options = listenerAPI.GetListenerConfiguredOptions(id)
		if msg.Error {
			msg.Level = messages.Debug
			core.MessageChannel <- msg
			return
		}
	case menu.LISTENERSETUP:
		// Get the options from the listener repository
		repo := memory.NewRepository()
		listener, err := repo.Get(id)
		if err != nil {
			msg := messages.UserMessage{
				Level:   messages.Debug,
				Message: fmt.Sprintf("there was an error getting the listener for ID %s: %s", id, err),
				Time:    time.Now().UTC(),
				Error:   true,
			}
			core.MessageChannel <- msg
			return
		}
		options = listener.Options()
	case menu.MODULE:
		repo := moduleMemory.NewRepository()
		module, err := repo.Get(id)
		if err != nil {
			msg := messages.UserMessage{
				Level:   messages.Debug,
				Message: fmt.Sprintf("there was an error getting the module for ID %s: %s", id, err),
				Time:    time.Now().UTC(),
				Error:   true,
			}
			core.MessageChannel <- msg
			return
		}
		options = module.GetMapFromOptions()
	}

	// Add the options to a slice
	resp := make([]string, 0)
	for k := range options {
		resp = append(resp, k)
	}

	if m == menu.MODULE {
		comp = readline.PcItem(c.name,
			readline.PcItem("Agent",
				readline.PcItemDynamic(completer.AgentListCompleterAll()),
			),
			readline.PcItemDynamic(completer.ListCompleter(resp)),
		)
	} else {
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(completer.ListCompleter(resp)),
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
	case menu.LISTENER:
		return c.DoListener(id, arguments)
	case menu.LISTENERSETUP:
		return c.DoListenerSetup(id, arguments)
	case menu.MODULE:
		return c.DoModule(id, arguments)
	}
	return
}

// DoListener handles the command arguments for the listener menu
func (c *Command) DoListener(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	h := c.help[menu.LISTENER]
	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	// Make sure there are at least 2 arguments (key and value)
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: h.Usage(),
			Time:    time.Now().UTC(),
		}
		return
	}
	msg := listenerAPI.SetOption(id, args)
	response.Message = &msg
	return
}

// DoListenerSetup handles the command arguments for the listener menu
func (c *Command) DoListenerSetup(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	h := c.help[menu.LISTENERSETUP]
	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	// Make sure there are at least 2 arguments (key and value)
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: h.Usage(),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error getting the listener for ID %s: %s", id, err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	options := listener.Options()

	if _, ok := options[args[1]]; !ok {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is not a valid option for this listener", args[1]),
			Time:    time.Now().UTC(),
		}
		return
	}

	options[args[1]] = args[2]
	err = repo.Update(id, options)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error updating the '%s' option for listener ID %s: %s", args[1], id, err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	response.Message = &messages.UserMessage{
		Level:   messages.Success,
		Message: fmt.Sprintf("set '%s' to: %s", args[1], args[2]),
		Time:    time.Now().UTC(),
	}
	return
}

// DoModule handles the command arguments for the module menu
func (c *Command) DoModule(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	h := c.help[menu.MODULE]
	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	// Make sure there are at least 2 arguments (key and value)
	// 0. set, 1. key, 2. value
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: h.Usage(),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Get options from the local repository
	repo := moduleMemory.NewRepository()
	m, err := repo.Get(id)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("pkg/cli/commands/info.DoModule(): there was an error getting module ID %s from the repository", err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		err = nil
		return
	}

	var message string
	if strings.ToLower(args[1]) == "agent" {
		message, err = m.SetAgent(args[2])
	} else {
		// Update the value
		message, err = m.SetOption(args[1], args[2:])
	}
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("pkg/cli/commands/set.DoModule(): there was an error setting the '%s' to '%s': %s", args[1], args[2:], err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		err = nil
		return
	}
	// Store the updated module
	err = repo.Update(id, m)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("pkg/cli/commands/set.DoModule(): there was an error storing the updated module: %s", err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		err = nil
		return
	}
	response.Message = &messages.UserMessage{
		Level:   messages.Success,
		Message: message,
		Time:    time.Now().UTC(),
	}
	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	h, ok := c.help[m]
	if !ok {
		return help.NewHelp(fmt.Sprintf("the 'info' command's Help structure does not exist for the %s menu", m), "", "", "")
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
