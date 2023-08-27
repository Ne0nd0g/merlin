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

package exclamation

import (
	// Standard
	"fmt"
	"os/exec"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
	uuid "github.com/satori/go.uuid"

	// Internal
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
	cmd.name = "!"
	cmd.menus = []menu.Menu{menu.ALLMENUS}
	cmd.os = os.LOCAL
	description := "Execute a command on the local system"
	usage := "! command [args]"
	example := "Merlin» ! ip a show ens32\n\n" +
		"\t[i] Executing system command...\n\n" +
		"\t[+] 2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n" +
		"\t    link/ether 00:0c:29:z3:ff:91 brd ff:ff:ff:ff:ff:ff\n" +
		"\t    inet 192.168.211.221/24 brd 192.168.211.255 scope global dynamic noprefixroute ens32\n" +
		"\t       valid_lft 1227sec preferred_lft 1227sec\n" +
		"\t    inet6 fe80::a71d:1f6a:a0d1:7985/64 scope link noprefixroute\n" +
		"\t       valid_lft forever preferred_lft forever\n" +
		"\tMerlin»"
	notes := "Include a space after the exclamation point. This command is useful so that you can execute " +
		"system commands without having to leave the CLI."
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
	args, err := shellwords.Parse(arguments)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Error:   true,
			Message: fmt.Sprintf("there was an error parsing the arguments: %s", err),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

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

	var arg []string
	if len(args) > 2 {
		arg = args[2:]
	}

	var cmd *exec.Cmd
	if len(arg) > 0 {
		cmd = exec.Command(args[1], arg...) // #nosec G204 Users can execute any arbitrary command by design
	} else {
		cmd = exec.Command(args[1]) // #nosec G204 Users can execute any arbitrary command by design
	}

	msg := messages.UserMessage{
		Level: messages.Success,
		Time:  time.Now().UTC(),
	}

	stdout, stderr := cmd.CombinedOutput()
	if cmd.Process != nil {
		msg.Message = fmt.Sprintf("Executed '%s' command on the local system with a process ID of %d\n\n%s", args[1], cmd.Process.Pid, string(stdout))
	} else {
		msg.Message = fmt.Sprintf("Executed '%s' command on the local system\n\n%s", args[1], string(stdout))
	}
	if stderr != nil {
		msg.Message += fmt.Sprintf("\n%s", stderr)
		msg.Level = messages.Warn
		msg.Error = true
	}
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
