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

package ps

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
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
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
	cmd.name = "ps"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "List running processes"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "ps"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]]» ps\n" +
		"\t[-] Created job afYByFZoXV for agent c1090dbc-f2f7-4d90-a241-86e0c0217786]\n" +
		"\t[-] Results job afYByFZoXV for agent c1090dbc-f2f7-4d90-a241-86e0c0217786]\n" +
		"\t[+]\n" +
		"\tPID     PPID    ARCH    OWNER   EXE\n" +
		"\t0       0       x64             [System Process]\n" +
		"\t4       0       x64             System\n" +
		"\t124     4       x64             Registry\n" +
		"\t412     4       x64             smss.exe\n" +
		"\t508     496     x64             csrss.exe\n" +
		"\t596     496     x64             wininit.exe\n" +
		"\t604     588     x64             csrss.exe\n" +
		"\t668     588     x64     BUILTIN\\Administrators  winlogon.exe\n" +
		"\t736     596     x64             services.exe\n" +
		"\t<SNIP>\n" +
		"\t4648    2504    x64     DESKTOP-H39FR21\\bob     sihost.exe\n" +
		"\t5732    736     x64     DESKTOP-H39FR21\\bob     svchost.exe\n" +
		"\t5684    736     x64     DESKTOP-H39FR21\\bob     svchost.exe\n" +
		"\t5768    1844    x64     DESKTOP-H39FR21\\bob     taskhostw.exe\n" +
		"\t5716    736     x64     BUILTIN\\Administrators  svchost.exe\n" +
		"\t2396    736     x64     NT AUTHORITY\\SYSTEM     svchost.exe\n" +
		"\t6220    2396    x64     DESKTOP-H39FR21\\bob     ctfmon.exe\n" +
		"\t6464    736     x64     NT AUTHORITY\\LOCAL SERVICE      svchost.exe\n" +
		"\t6504    6376    x64     DESKTOP-H39FR21\\bob     explorer.exe"
	notes := "This command is only available to agent running on a Windows operating system! This command uses " +
		"the Windows API to gather available information about running processes. The agent is not running in a " +
		"high-integrity process then some of the information will be missing."
	cmd.help = help.NewHelp(description, example, notes, usage)
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

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	msg := agentAPI.PS(id)
	response.Message = &msg
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
