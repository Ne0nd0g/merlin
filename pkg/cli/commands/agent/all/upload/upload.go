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

package upload

import (
	// Standard
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	os2 "os"
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
	cmd.name = "upload"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Upload a file to the target system"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "upload sourceFilePath destinationFilePath"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» " +
		"upload C:\\\\SysinternalsSuite\\\\PsExec.exe C:\\\\Windows\\\\PsExec.exe\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»" +
		"\t[-]Created job vXJsZdZLPP for agent c1090dbc-f2f7-4d90-a241-86e0c0217786"
	notes := "NOTE: Because \\ is used to escape a character, file paths require two (e.g., C:\\\\Windows). " +
		"Enclose file paths containing a space with quotation marks (e.g.,. \"C:\\\\Windows\\\\Program Files\\\\\")"
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

	// 0. upload, 1. source file path, 2. destination file path
	if len(args) < 3 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires a source and destination file path:\n%s", c, c.help.Usage()))
		return
	}

	// Validate source file exists
	_, err = os2.Stat(args[1])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("the file at '%s' does not exist:\n%s", args[1], c.help.Usage()))
		return
	}

	// Read in the file
	data, err := os2.ReadFile(args[1])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error reading the file at %s: %s", args[1], err))
		return
	}

	// Generate and log filepath and hash
	fileHash := sha256.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
	_, err = io.WriteString(fileHash, string(data))
	if err != nil {
		slog.Error(fmt.Sprintf("there was an error generating tha SHA256 file hash for %s: %s", args[1], err))
	} else {
		slog.Info("Uploading file from the 'load-assembly' command", "filepath", args[1], "SHA256", hex.EncodeToString(fileHash.Sum(nil)))
	}

	response.Message = rpc.Upload(id, []string{base64.StdEncoding.EncodeToString(data), args[2]})
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
