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

package load_assembly

import (
	// Standard
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	os2 "os"
	"path/filepath"
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
	cmd.name = "load-assembly"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Load a .NET assembly into the agent’s process."
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "load-assembly filePath [alias]"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly /root/Rubeus.exe\n" +
		"\t[-] Created job iQOkWgGqkJ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job iQOkWgGqkJ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] successfully loaded rubeus.exe into the default AppDomain\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly /root/Rubeus.exe Hagrid\n" +
		"\t[-] Created job YrPdQkcuTG for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job YrPdQkcuTG for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] successfully loaded Hagrid into the default AppDomain"
	notes := "Once the assembly is loaded, it can be executed multiple times with the invoke-assembly command." +
		" The .NET assembly is only sent across the wire one time. An option third argument can be provided to " +
		"reference the assembly as any other name when executed with the invoke-assembly command.\n\n" +
		"\tNote\n\n" +
		"\tOnly CLR v4 is currently supported which can be used to execute both v3.5 and v4 .NET assemblies"
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
	args := strings.Split(arguments, " ")

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()))
		return
	}

	// Check for help first
	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
		return
	}
	// 0. load-assembly
	// 1. assemblyPath
	// 2. alias

	// Validate that file path exists
	_, err := os2.Stat(args[1])
	if os2.IsNotExist(err) {
		response.Message = message.NewErrorMessage(fmt.Errorf("the file path does not exist: %s", args[1]))
		return
	}
	// Read in the file
	data, err := os2.ReadFile(args[1])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error reading the file at %s: %s", args[1], err))
		return
	}
	var name string
	if len(args) > 2 {
		name = args[2]
	} else {
		name = filepath.Base(args[1])
	}

	// Generate and log filepath and hash
	fileHash := sha256.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
	_, err = io.WriteString(fileHash, string(data))
	if err != nil {
		slog.Error(fmt.Sprintf("there was an error generating tha SHA256 file hash for %s: %s", args[1], err))
	} else {
		slog.Info("Uploading file from the 'load-assembly' command", "filepath", args[1], "SHA256", hex.EncodeToString(fileHash.Sum(nil)))
	}

	response.Message = rpc.LoadAssembly(id, []string{base64.StdEncoding.EncodeToString(data), name, hex.EncodeToString(fileHash.Sum(nil))})
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
