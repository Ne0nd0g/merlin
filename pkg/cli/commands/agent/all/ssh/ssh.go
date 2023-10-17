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

package ssh

import (
	// Standard
	"fmt"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
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
	name   string      // name is the name of the command
	help   help.Help   // help is the Help structure for the command
	menus  []menu.Menu // menu is the Menu the command can be used in
	native bool        // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS       // os is the supported operating system the Agent command can be executed on
}

// NewCommand is a factory that builds and returns a Command structure that implements the Command interface
func NewCommand() *Command {
	var cmd Command
	cmd.name = "ssh"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Execute a command on a remote host via SSH"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "ssh username password host:port program [args]"
	example := "Merlin[agent][fbef5b71-50bb-4d36-8a1b-2edf233eb578]» " +
		"ssh rastley S3cretPassw0rd 192.168.100.123:22 /bin/sh -c \\\"ip address show eth0\\\"\n" +
		"\t[-] Created job pinIDJXDTv for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job pinIDJXDTv for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] Connected to 192.168.100.123:22 at 192.168.100.123:22 with public key ecdsa-sha2-nistp256 " +
		"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJytZseMSAsUU6OE2X4TC518fcF3yxgFYIgYp4+xT9pa9n5449gcsKT/eO" +
		"3hx9NXAtyOHImg/Ff8kdWs52bU3SA=\n" +
		"\t0: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n" +
		"\t    link/ether 00:0c:29:z3:ff:91 brd ff:ff:ff:ff:ff:ff\n" +
		"\t    inet 192.168.100.70/24 brd 192.168.100.255 scope global dynamic noprefixroute eth0\n" +
		"\t       valid_lft 1781sec preferred_lft 1781sec"
	notes := "WARNING: This command is insecure by design because it does not validate the remote host’s public key"
	cmd.help = help.NewHelp(description, example, notes, usage)
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
	// Parse the arguments
	args, err := shellwords.Parse(arguments)
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing the arguments: %s", err))
		err = nil
		return
	}

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
			return
		}
	}

	// 0. ssh, 1. username, 2. password, 3. host:port, 4. program, 5. args
	if len(args) < 5 {
		response.Message = message.NewErrorMessage(fmt.Errorf("'%s' command requires at least 4 arguments\n%s", c, c.help.Usage()))
		return
	}
	response.Message = rpc.SSH(id, args[1:])
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
