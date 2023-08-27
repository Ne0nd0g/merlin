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

package execute_assembly

import (
	// Standard
	"fmt"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
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
	cmd.name = "execute-assembly"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Execute .NET assembly as shellcode in a child process"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "execute-assembly assemblyPath [assemblyArguments] [spawnToPath] [spawnToArguments]"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly Seatbelt.exe " +
		"\"DotNet IdleTime\" \"C:\\\\Windows\\\\System32\\\\WerFault.exe\" /?\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»\n" +
		"\t[-] Created job dmAfzDPUsM for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n\n" +
		"\t[+] Results for c1090dbc-f2f7-4d90-a241-86e0c0217786 job dmAfzDPUsM\n\n\n\n" +
		"\t                        %&&@@@&&\n" +
		"\t                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%\n" +
		"\t                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%\n" +
		"\t%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((\n" +
		"\t#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((\n" +
		"\t#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((\n" +
		"\t#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((\n" +
		"\t#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####\n" +
		"\t###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####\n" +
		"\t#####%######################  %%%..                       @////(((&%%%%%%%################\n" +
		"\t                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*\n" +
		"\t                        &%%&&&%%%%%        v1.1.0         ,(((&%%%%%%%%%%%%%%%%%,\n" +
		"\t                         #%%%%##,\n\n\n" +
		"\t====== DotNet ======\n\n" +
		"\t  Installed CLR Versions\n" +
		"\t      2.0.50727\n" +
		"\t      4.0.30319\n\n" +
		"\t  Installed .NET Versions\n" +
		"\t      3.5.30729.4926\n" +
		"\t      4.8.03752\n\n" +
		"\t  Anti-Malware Scan Interface (AMSI)\n" +
		"\t      OS supports AMSI           : True\n" +
		"\t     .NET version support AMSI   : True\n" +
		"\t        [!] The highest .NET version is enrolled in AMSI!\n" +
		"\t        [*] You can invoke .NET version 3.5 to bypass AMSI.\n" +
		"\t====== IdleTime ======\n\n" +
		"\t  CurrentUser : DESKTOP-H35RK21\\rastley\n" +
		"\t  Idletime    : 00h:06m:02s:766ms (362766 milliseconds)\n\n\n\n" +
		"\t[*] Completed collection in 0.122 seconds"
	notes := "Uses go-donut to convert a .NET assembly into shellcode and then uses the windows/x64/go/exec/createProcess Merlin module to execute the shellcode. " +
		"The command requires the file path to the assembly you wish to execute in the <assembly path> " +
		"argument.All other arguments are optional. The <spawnto path> argument is the process that will be started on " +
		"the target and where the shellcode will be injected and executed. If a <spawnto path> is not provided, " +
		"C:\\WIndows\\System32\\dllhost.exe will be used. The <spawnto args> value is used as an argument when starting " +
		"the spawnto process.\n\n" +
		"\tCurrently this command only supports .NET v4.0 assemblies. For more granular control, use the 'windows/x64/go/exec/donut' module.\n\n" +
		"\tBecause \\ is used to escape a character, file paths require two (e.g., C:\\\\Windows)\n\n" +
		"\tUse quotes to enclose multiple arguments for <assembly args> (e.g., execute-assembly Seatbelt.exe \"LocalGroups LocalUsers\")"
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
	msg := agentAPI.ExecuteAssembly(id, args)
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
