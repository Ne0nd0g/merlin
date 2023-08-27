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

package show

import (
	// Standard
	"fmt"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Internal
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
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
	cmd.name = "show"
	cmd.menus = []menu.Menu{menu.LISTENER, menu.LISTENERSETUP, menu.MODULE}
	cmd.os = os.ALL
	cmd.help = make(map[menu.Menu]help.Help)

	// Help for LISTENER
	listenerDescription := "Show a table of the Listener's configurable options"
	listenerUsage := "show"
	listenerExample := "Merlin[listeners][0ae39696-3fe8-499b-8e14-61d3eb8c0d9c]» show\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t|     NAME      |                    VALUE                     |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| X509Cert      |                                              |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Name          | My HTTP Listener                             |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Port          | 443                                          |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| JWTLeeway     | 1m0s                                         |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| PSK           | NeverGonnaGiveYouUp                          |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Protocol      | HTTPS                                        |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Interface     | 127.0.0.1                                    |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Authenticator | OPAQUE                                       |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| JWTKey        | Vmx3TEl6dnNKVndITHpXd3lET25IYlh0dld3aHBJQmw= |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Description   | Default HTTP Listener                        |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| ID            | 0ae39696-3fe8-499b-8e14-61d3eb8c0d9c         |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Transforms    | jwe,gob-base,                                |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| URLS          | /                                            |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| X509Key       |                                              |\n" +
		"\t+---------------+----------------------------------------------+\n" +
		"\t| Status        | Running                                      |\n" +
		"\t+---------------+----------------------------------------------+"
	listenerNotes := ""
	cmd.help[menu.LISTENER] = help.NewHelp(listenerDescription, listenerExample, listenerNotes, listenerUsage)
	cmd.help[menu.LISTENERSETUP] = help.NewHelp(listenerDescription, listenerExample, listenerNotes, listenerUsage)

	// Help for Module menu
	moduleDescription := "Show the module's configurable options"
	moduleExample := "\n\tMerlin» modules \n" +
		"\tMerlin[modules]» use windows/x64/powershell/powersploit/PowerUp \n" +
		"\tMerlin[modules][windows/x64/powershell/powersploit/PowerUp]» show\n" +
		"\tMerlin[modules][windows/x64/powershell/powersploit/PowerUp]»  \n" +
		"\t[i] \n" +
		"\t'PowerUp' module options\n\n" +
		"\t     NAME    |                VALUE                 | REQUIRED |          DESCRIPTION            \n" +
		"\t+------------+--------------------------------------+----------+--------------------------------+\n" +
		"\t  Agent      | 00000000-0000-0000-0000-000000000000 | true     | Agent on which to run module    \n" +
		"\t             |                                      |          | PowerUp                         \n" +
		"\t  HTMLReport |                                      | false    | Switch. Write a HTML            \n" +
		"\t             |                                      |          | version of the report to        \n" +
		"\t             |                                      |          | SYSTEM.username.html.           \n\n"
	moduleNotes := "use the 'set` command to change the value of a configurable option"
	moduleUsage := "show"
	cmd.help[menu.MODULE] = help.NewHelp(moduleDescription, moduleExample, moduleNotes, moduleUsage)

	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {
	if core.Debug {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Debug,
			Message: fmt.Sprintf("entering into Completer() for the '%s' command with Menu: %s, and id: %s", c, m, id),
			Time:    time.Now().UTC(),
		}
	}
	return readline.PcItem(c.name)
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

// DoListener handles the command arguments for the LISTENER menu
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
				Message: fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	msg, options := listenerAPI.GetListenerConfiguredOptions(id)
	if msg.Error {
		response.Message = &msg
		return
	}
	msg = listenerAPI.GetListenerStatus(id)
	if msg.Error {
		response.Message = &msg
		return
	}

	if options != nil {
		tableString := &strings.Builder{}
		table := tablewriter.NewWriter(tableString)
		table.SetHeader([]string{"Name", "Value"})
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetRowLine(true)
		table.SetBorder(true)

		for k, v := range options {
			table.Append([]string{k, v})
		}
		table.Append([]string{"Status", msg.Message})
		table.Render()

		response.Message = &messages.UserMessage{
			Level:   messages.Plain,
			Message: tableString.String(),
			Time:    time.Now().UTC(),
		}
	}
	return
}

// DoListenerSetup handles the command arguments for the LISTENERSETUP menu
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
	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		return
	}

	// Set up the table
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Name", "Value"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowLine(true)
	table.SetBorder(true)

	for k, v := range listener.Options() {
		table.Append([]string{k, v})
	}
	table.Render()

	response.Message = &messages.UserMessage{
		Level:   messages.Plain,
		Message: tableString.String(),
		Time:    time.Now().UTC(),
	}
	return
}

func (c *Command) DoModule(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		h := c.help[menu.MODULE]
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description, h.Usage, h.Example, h.Notes),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	// Get options from the local repository
	repo := moduleMemory.NewRepository()
	m, err := repo.Get(id)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("pkg/cli/commands/show.DoModule(): there was an error getting module ID %s from the repository", err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		err = nil
		return
	}

	message := fmt.Sprintf("\n'%s' module options\n\n", m.Name)
	// Build the table of options
	builder := &strings.Builder{}
	table := tablewriter.NewWriter(builder)
	table.SetHeader([]string{"Name", "Value", "Required", "Description"})
	table.SetBorder(false)
	table.Append([]string{"Agent", m.Agent.String(), "true", "Agent on which to run module " + m.Name})
	for _, v := range m.Options {
		table.Append([]string{v.Name, v.Value, strconv.FormatBool(v.Required), v.Description})
	}
	table.Render()
	message += builder.String()

	response.Message = &messages.UserMessage{
		Level:   messages.Info,
		Message: message,
		Time:    time.Now().UTC(),
	}

	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	h, ok := c.help[m]
	if !ok {
		return help.NewHelp(fmt.Sprintf("the 'show' command's Help structure does not exist for the %s menu", m), "", "", "")
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
