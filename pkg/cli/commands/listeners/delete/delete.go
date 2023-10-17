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

package delete

import (
	// Standard
	"bufio"
	"fmt"
	os2 "os"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"

	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/completer"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
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
	cmd.name = "delete"
	cmd.menus = []menu.Menu{menu.LISTENER, menu.LISTENERS}
	cmd.os = os.LOCAL
	description := "Stop and remove a listener from the Server"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "delete [listenerID]"
	example := "Merlin[listeners][fb1f0123-9125-449b-a0d4-1c327ebbe622]» delete\n\n" +
		"\tAre you sure you want to delete the fb1f0123-9125-449b-a0d4-1c327ebbe622 listener? [yes/NO]: \n" +
		"\tyes\n" +
		"\tMerlin[listeners]»  \n" +
		"\t[+] deleted listener fb1f0123-9125-449b-a0d4-1c327ebbe622\n"
	notes := "Confirmation is required to proceed.\n\tUse tab to cycle through available listeners. " +
		"The listener's ID is not required if you're already interacting with it."
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {

	return readline.PcItem(c.name,
		readline.PcItemDynamic(completer.ListenerListCompleter()),
	)
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		}
	}
	switch m {
	case menu.LISTENERS:
		if len(args) < 2 {
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()))
			return
		}
		// Parse the UUID
		var err error
		id, err = uuid.FromString(args[1])
		if err != nil {
			response.Message = message.NewErrorMessage(fmt.Errorf("invalid UUID: %s\n%s", args[1], c.help.Usage()))
			return
		}
	}

	if confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", id)) {
		response.Message = rpc.RemoveListener(id)
		if !response.Message.Error() {
			response.Menu = menu.LISTENERS
			response.Prompt = "\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m "
		}
	}
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

// confirm reads in a string and returns true if the string is y or yes but does not provide the prompt question
func confirm(question string) bool {
	reader := bufio.NewReader(os2.Stdin)
	core.STDOUT.Lock()
	defer core.STDOUT.Unlock()

	fmt.Println(color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)))

	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(color.RedString("Error reading input: %s", err))
		return false
	}

	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")
	yes := []string{"y", "yes", "-y", "-Y"}

	for _, match := range yes {
		if response == match {
			return true
		}
	}
	return false
}
