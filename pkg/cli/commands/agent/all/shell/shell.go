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

package shell

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
	cmd.name = "shell"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Execute commands through the host's default command shell"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "shell command [arguments]"
	example := "Example using ver:\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell ver\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»" +
		"\t[-]Created job IxVXgyIkhS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+]Results for job IxVXgyIkhS\n\n" +
		"\tMicrosoft Windows [Version 10.0.16299.64]"
	notes := "On Windows the %COMSPEC% shell is used and if it is cmd.exe then the /c argument is used. " +
		"For macOS and Linux, the /bin/sh shell is used with the -c argument. Use the run command to execute a program " +
		"directly without invoking the shell.\n\n" +
		"\tShell Functions\n\n" +
		"\tSome commands and capabilities are components of a shell and can ONLY be used with a shell. For example, the " +
		"'dir' command is a component of cmd.exe and is not its own program executable. Therefore, dir can only be used" +
		" within the cmd.exe shell.\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell dir\n\n" +
		"\tThe pipe and redirection characters | , > , and < , are also functions of a shell environment.\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell \"cat /etc/passwd | grep root\"\n\n" +
		"\tQuoted Arguments\n\n" +
		"\tWhen running a command on an agent from the server, the provided arguments are passed to executable that was " +
		"called. As long as there are no special characters (e.g., \\ , & , ; , | , > , < etc.) the command will be " +
		"processed fine.\n\n" +
		"\tFor example, this command will work fine because it does not have any special characters:\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe Get-Service -Name win* -Exclude WinRM\n\n" +
		"\tHowever, this command WILL fail because of the | symbol. The command will still execute, but will stop " +
		"\tprocessing everything after the | symbol.\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe Get-Service -Name win* -Exclude WinRM | fl\n\n" +
		"\tTo circumvent this, enclose the entire argument in quotes. The outer most quotes will be removed when the " +
		"arguments are passed. The argument can be enclosed in double quotes or single quotes. All other quotes need to " +
		"be escaped The command be executed in both of these ways:\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe \"Get-Service -Name win* -Exclude WinRM | fl\"\n\n" +
		"\tOR\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe \"Get-Service -Name \\\"win*\\\" -Exclude \"WinRM\" | fl\"\n\n" +
		"\tOR\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell powershell.exe 'Get-Service -Name \\'win*\\' -Exclude 'WinRM' | fl'\n\n" +
		"\tEscape Sequence\n\n" +
		"\tFollowing along with the Quoted Arguments section above, the \\ symbol will be interpreted as an escape " +
		"sequence. This is beneficial because it can be used to escape other characters like the pipe symbol, | . " +
		"However, it can work against you when working with Windows file paths and the arguments are not enclosed in quotes.\n\n" +
		"\tThis command will fail because the \\ itself needs to escaped. Notice the error message shows File Not Found:\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell dir C:\\Windows\\System32\n" +
		"\t[-]Created job hBYxRfaRBG for agent 21a0fc5f-14ad-4c43-b41e-57eab1feb0e1\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»\n" +
		"\t[+]Results for job hBYxRfaRBG\n" +
		"\t[+]  Volume in drive C has no label.\n" +
		"\tVolume Serial Number is AC57-CFB9\n\n" +
		"\tDirectory of C:\\\n\n" +
		"\tFile Not Found\n\n" +
		"To correctly issue the command either escape the \\ or enclose the commands in quotes:\n\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» shell dir C:\\\\Windows\\\\System32\n\n"
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
	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()))
		return
	}

	response.Message = rpc.CMD(id, args)
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
