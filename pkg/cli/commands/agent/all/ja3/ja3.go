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

package ja3

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
	cmd.name = "ja3"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Change the Agent's JA3 TLS signature to the one provided"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "ja3 signature"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ja3 " +
		"769,49161-49171-47-49156-49166-51-50-49159-49169-5-49154-49164-49160-49170-10-49155-49165-22-19-4-255,10-11-0," +
		"23-1-3-19-21-6-7-9-10-24-11-12-25-13-14-15-16-17-2-18-4-5-20-8-22,0\n"
	notes := "JA3 is a method for fingerprinting TLS clients on the wire. Every TLS client has a unique " +
		"signature depending on its configuration of the following TLS options: " +
		"SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats.\n\n" +
		"\tThe ja3 option allows the agent to create a TLS client based on the provided JA3 hash signature. " +
		"This is useful to evade detections based on a JA3 hash for a known tool (e.g.,. Merlin). " +
		"Known JA3 signatures can be downloaded from https://ja3er.com/\n\n" +
		"\tWARNING: Make sure the input JA3 hash will enable communications with the Server. " +
		"For example, if you leverage a JA3 hash that only supports SSLv2 and the server does not support that " +
		"protocol, then they will not be able to communicate. The -ja3 flag will override the the -proto flag and " +
		"will cause the agent to use the protocol provided in the JA3 hash.\n\n" +
		"\tThis example will create a TLS client with a JA3 hash of 51a7ad14509fd614c7bb3a50c4982b8c that matches " +
		"Java based malware such as Neutrino and Nuclear Exploit Kit (EK)."
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
	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()),
			Time:    time.Now().UTC(),
		}
		return
	}

	msg := agentAPI.JA3(id, args)
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
