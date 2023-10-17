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

package memory

import (
	// Standard
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	// 3rd Party
	"github.com/chzyer/readline"
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
	cmd.name = "memory"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Read, write, or patch the Agent process' virtual memory"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "memory {read|write|patch} module procedure {readLength | hexData}"
	example := ""
	notes := "Uses direct syscalls for NtReadVirtualMemory, NtProtectVirtualMemory, & ZwWriteVirtualMemory " +
		"implemented using BananaPhone at https://github.com/C-Sto/BananaPhone"
	cmd.help = help.NewHelp(description, example, notes, usage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface {

	comp := readline.PcItem(c.name,
		readline.PcItem("read"),
		readline.PcItem("patch"),
		readline.PcItem("write"),
	)
	return comp
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()))
		return
	}

	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
		return
	case "patch":
		return c.Patch(id, arguments)
	case "read":
		return c.Read(id, arguments)
	case "write":
		return c.Write(id, arguments)
	default:
		response.Message = message.NewUserMessage(message.Warn, fmt.Sprintf("'%s' is not a valid argument for the '%s' command\n%s", args[1], c, c.help.Usage()))
		return
	}
}

// Patch overwrites the starting bytes at the specified function with the provided data
func (c *Command) Patch(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "patch"

	description := "Overwrites the starting bytes at the specified function with the provided data"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory patch ntdll.dll EtwEventWrite 9090C3\n" +
		"\t[-] Created job quRORyMMxS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job quRORyMMxS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+]\n" +
		"\tRead  3 bytes from ntdll.dll!EtwEventWrite: 4C8BDC\n" +
		"\tWrote 3 bytes to   ntdll.dll!EtwEventWrite: 9090C3\n" +
		"\tRead  3 bytes from ntdll.dll!EtwEventWrite: 9090C3"
	usage := "memory patch module function bytes"
	notes := "This command locates the address of the provided procedure/function, reads the existing bytes, " +
		"and the overwrites them with the provided bytes. A second read is performed to validate the write event. " +
		"The command would be the same as calling the read and write commands individually. The bytes should be provided in hex format."
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	// 0. memory, 1. patch, 2. help
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command help\n\n"+
				"Description:\n\t%s\n"+
				"Usage:\n\t%s\n"+
				"Example:\n\t%s\n"+
				"Notes:\n\t%s",
				c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// 0. memory, 1. patch, 2. module, 3. function, 4. bytes
	if len(args) < 5 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command requires four arguments\n%s", c, sub, h.Usage()))
		return
	}

	// Validate the bytes are in hex format
	if _, err := hex.DecodeString(args[4]); err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("'%s' is not a valid hex string\n%s", args[4], h.Usage()))
		return
	}
	response.Message = rpc.Memory(id, args[1:])
	return
}

// Read returns the starting bytes at the specified function
func (c *Command) Read(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "read"

	description := "Reads the starting bytes at the specified function"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory read ntdll.dll EtwEventWrite 3\n" +
		"\t[-] Created job YlqClnqRdK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job YlqClnqRdK for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+] Read 3 bytes from ntdll.dll!EtwEventWrite: 4C8BDC"
	usage := "memory read module function length"
	notes := ""
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command help\n\n"+
				"Description:\n\t%s\n"+
				"Usage:\n\t%s\n"+
				"Example:\n\t%s\n"+
				"Notes:\n\t%s",
				c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// 0. memory, 1. read, 2. module, 3. function, 4. length
	if len(args) < 5 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command requires four arguments\n%s", c, sub, h.Usage()))
		return
	}

	// Validate the length is an integer
	if _, err := strconv.Atoi(args[4]); err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error converting %s to an integer\n%s", args[4], c.help.Usage()))
		return
	}
	response.Message = rpc.Memory(id, args[1:])
	return
}

// Write overwrites the starting bytes at the specified function with the provided data
func (c *Command) Write(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "write"

	description := "Writes the provided bytes to the start of the specified function"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory write ntdll.dll EtwEventWrite 9090C3\n" +
		"\t[-] Created job XTXJBLoZuO for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job XTXJBLoZuO for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+]\n" +
		"\tWrote 3 bytes to ntdll.dll!EtwEventWrite: 9090C3"
	usage := "memory write module function bytes"
	notes := "The bytes should be provided in hex format."
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	// 0. memory, 1. write, 2. help
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command help\n\n"+
				"Description:\n\t%s\n"+
				"Usage:\n\t%s\n"+
				"Example:\n\t%s\n"+
				"Notes:\n\t%s",
				c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// 0. memory, 1. write, 2. module, 3. function, 4. bytes
	if len(args) < 5 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s %s' command requires four arguments\n%s", c, sub, h.Usage()))
		return
	}
	// Validate the bytes are in hex format
	if _, err := hex.DecodeString(args[4]); err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error decoding the bytes '%s':%s\n%s", args[4], err, h.Usage()))
		return
	}
	response.Message = rpc.Memory(id, args[1:])
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
