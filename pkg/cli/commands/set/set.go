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
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
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
	cmd.name = "set"
	cmd.menus = []menu.Menu{menu.LISTENERSETUP}
	cmd.os = os.LOCAL
	cmd.help.Description = "Set a configurable option"
	cmd.help.Usage = "set <option> <value>"
	cmd.help.Example = "Merlin[listeners]» use https\n" +
		"Merlin[listeners][https]» set Name Merlin Demo Listener\n" +
		"[+] set Name to: Merlin Demo Listener\n" +
		"Merlin[listeners][https]»"
	cmd.help.Notes = ""
	return &cmd
}

func (c *Command) Completer(id uuid.UUID) (readline.PrefixCompleterInterface, error) {
	// readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(options["Protocol"])),
	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		return nil, fmt.Errorf("there was an error getting the listener for ID %s: %s", id, err)
	}
	options := make([]string, 0)
	for k := range listener.Options() {
		options = append(options, k)
	}

	return readline.PcItem(c.name,
		readline.PcItemDynamic(optionCompleter(options)),
	), nil
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
	// Parse the arguments
	args := strings.Split(arguments, " ")
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
			message.Level = messages.Info
			message.Time = time.Now().UTC()
			return
		}
	}

	// Make sure there are at least 2 arguments (key and value)
	if len(args) < 3 {
		message.Message = c.Usage()
		message.Level = messages.Info
		message.Time = time.Now().UTC()
		return
	}

	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		message.Message = fmt.Sprintf("there was an error getting the listener for ID %s: %s", id, err)
		message.Level = messages.Warn
		message.Time = time.Now().UTC()
		return
	}
	options := listener.Options()

	if _, ok := options[args[1]]; !ok {
		message.Message = fmt.Sprintf("'%s' is not a valid option for this listener", args[1])
		message.Level = messages.Warn
		message.Time = time.Now().UTC()
		return
	}
	options[args[1]] = args[2]
	err = repo.Update(id, options)
	if err != nil {
		message.Message = fmt.Sprintf("there was an error updating the '%s' option for listener ID %s: %s", args[1], id, err)
		message.Level = messages.Warn
		message.Time = time.Now().UTC()
		return
	}
	message.Level = messages.Success
	message.Message = fmt.Sprintf("set '%s' to: %s", args[1], args[2])
	message.Time = time.Now().UTC()
	return
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

// optionCompleter returns a list of configurable listener options for command line tab completion
func optionCompleter(options []string) func(string) []string {
	return func(line string) []string {
		return options
	}
}
