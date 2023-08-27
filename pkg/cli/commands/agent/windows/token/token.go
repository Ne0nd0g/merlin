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

package token

import (
	// Standard
	"fmt"
	"strconv"
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
	cmd.name = "token"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.WINDOWS
	description := "Interact with Windows access tokens"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "token {make|privs|rev2self|steal|whoami} [options]"
	example := ""
	notes := "Merlin keeps track of when a Windows access token was created or stolen. If there is a created " +
		"or stolen token, it will be used with the following commands:\n" +
		"\t- cd\n" +
		"\t- download\n" +
		"\t- execute-assembly\n" +
		"\t- execute-pe\n" +
		"\t- execute-shellcode\n" +
		"\t- invoke-assembly\n" +
		"\t- minidump\n" +
		"\t- kill\n" +
		"\t- ls\n" +
		"\t- ps\n" +
		"\t- rm\n" +
		"\t- run\n" +
		"\t- shell\n" +
		"\t- touch\n" +
		"\t- upload\n\n" +
		"The following commands will make the Windows CreateProcessWithTokenW API call:\n" +
		"\t- execute-assembly\n" +
		"\t- execute-pe\n" +
		"\t- execute-shellcode\n" +
		"\t- run\n" +
		"\t- shell\n"
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
	comp := readline.PcItem("token",
		readline.PcItem("make"),
		readline.PcItem("privs"),
		readline.PcItem("rev2self"),
		readline.PcItem("steal"),
		readline.PcItem("whoami"),
	)
	return comp
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

	switch strings.ToLower(args[1]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()),
			Time:    time.Now().UTC(),
		}
	case "make":
		return c.Make(id, arguments)
	case "privs":
		return c.Privs(id, arguments)
	case "rev2self":
		return c.Rev2Self(id, arguments)
	case "steal":
		return c.Steal(id, arguments)
	case "whoami":
		return c.Whoami(id, arguments)
	default:
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: c.help.Usage(),
			Time:    time.Now().UTC(),
		}
	}
	return
}

func (c *Command) Make(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "make"

	description := "Create a new Windows access token"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token make ACME\\\\Administrator S3cretPassw0rd\n" +
		"\t[-] Created job piloeJbKPp for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job piloeJbKPp for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+] Successfully created a Windows access token for ACME\\Administrator with a logon ID of 0xA703CF0"
	notes := "Tokens are created with the Windows LogonUserW API call. " +
		"The token is created with a type 9 - NewCredentials logon type. " +
		"This is the equivalent of using runas.exe /netonly.\n" +
		"\tCommands such as 'token whoami' will show the username for the process and not the created token due to the " +
		"logon type, but will reflect the new Logon ID" +
		"\tWARNING: Type 9 - NewCredentials tokens only work for NETWORK authenticated activities\n" +
		"\tReferences:\n" +
		"\t\t- https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types"
	usage := "token make DOMAIN\\USERNAME PASSWORD"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	// 0. token, 1. make, 2. DOMAIN\USERNAME, 3. PASSWORD
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level: messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\n"+
					"Description:\n\t%s\n"+
					"Usage:\n\t%s\n"+
					"Example:\n\t%s\n"+
					"Notes:\n\t%s",
					c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time: time.Now().UTC(),
			}
			return
		}
	}

	if len(args) < 4 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires two arguments\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	msg := agentAPI.Token(id, args)
	response.Message = &msg
	return
}

func (c *Command) Privs(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "privs"

	description := "Enumerate token privileges for the current or remote process"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token privs\n" +
		"\t[-] Created job rBIkAAWkIr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job rBIkAAWkIr for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] Process ID 6892 access token integrity level: High, privileges (24):\n" +
		"\t        Privilege: SeIncreaseQuotaPrivilege, Attribute:\n" +
		"\t        Privilege: SeSecurityPrivilege, Attribute:\n" +
		"\t        Privilege: SeTakeOwnershipPrivilege, Attribute:\n" +
		"\t        Privilege: SeLoadDriverPrivilege, Attribute:\n" +
		"\t        Privilege: SeSystemProfilePrivilege, Attribute:\n" +
		"\t        Privilege: SeSystemtimePrivilege, Attribute:\n" +
		"\t        Privilege: SeProfileSingleProcessPrivilege, Attribute:\n" +
		"\t        Privilege: SeIncreaseBasePriorityPrivilege, Attribute:\n" +
		"\t        Privilege: SeCreatePagefilePrivilege, Attribute:\n" +
		"\t        Privilege: SeBackupPrivilege, Attribute:\n" +
		"\t        Privilege: SeRestorePrivilege, Attribute:\n" +
		"\t        Privilege: SeShutdownPrivilege, Attribute:\n" +
		"\t        Privilege: SeDebugPrivilege, Attribute: SE_PRIVILEGE_ENABLED\n" +
		"\t        Privilege: SeSystemEnvironmentPrivilege, Attribute:\n" +
		"\t        Privilege: SeChangeNotifyPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED\n" +
		"\t        Privilege: SeRemoteShutdownPrivilege, Attribute:\n" +
		"\t        Privilege: SeUndockPrivilege, Attribute:\n" +
		"\t        Privilege: SeManageVolumePrivilege, Attribute:\n" +
		"\t        Privilege: SeImpersonatePrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED\n" +
		"\t        Privilege: SeCreateGlobalPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED\n" +
		"\t        Privilege: SeIncreaseWorkingSetPrivilege, Attribute:\n" +
		"\t        Privilege: SeTimeZonePrivilege, Attribute:\n" +
		"\t        Privilege: SeCreateSymbolicLinkPrivilege, Attribute:\n" +
		"\t        Privilege: SeDelegateSessionUserImpersonatePrivilege, Attribute:\n\n" +
		"\tRemote process:\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token privs 8156\n" +
		"\t[-] Created job BAKadQhkOc for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job BAKadQhkOc for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] Process ID 8156 access token integrity level: Low, privileges (2):\n" +
		"\t        Privilege: SeChangeNotifyPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED\n" +
		"\t        Privilege: SeIncreaseWorkingSetPrivilege, Attribute:"
	notes := ""
	usage := "token privs [PID]"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level: messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\n"+
					"Description:\n\t%s\n"+
					"Usage:\n\t%s\n"+
					"Example:\n\t%s\n"+
					"Notes:\n\t%s",
					c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time: time.Now().UTC(),
			}
			return
		}
	}

	// If a PID was provided, validate it is an integer
	if len(args) > 3 {
		_, err := strconv.Atoi(args[2])
		if err != nil {
			response.Message = &messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("There was an error converting '%s' to an integer: %s", args[2], err),
				Time:    time.Now().UTC(),
				Error:   true,
			}
			return
		}
	}

	msg := agentAPI.Token(id, args)
	response.Message = &msg
	return
}

func (c *Command) Rev2Self(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "rev2self"

	description := "Revert the thread impersonation token to the process token"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token rev2self\n" +
		"\t[-] Created job ZXKyKuIZru for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job ZXKyKuIZru for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] Successfully reverted to self and dropped the impersonation token"
	notes := "Leverages the RevertToSelf Windows API function. There is 'rev2sef' command alias.\n" +
		"\tReferences:\n" +
		"\t\t- https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself"
	usage := "rev2self"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. token, 1. rev2self, 2. -h
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level: messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\n"+
					"Description:\n\t%s\n"+
					"Usage:\n\t%s\n"+
					"Example:\n\t%s\n"+
					"Notes:\n\t%s",
					c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time: time.Now().UTC(),
			}
			return
		}
	}
	msg := agentAPI.Token(id, args)
	response.Message = &msg
	return
}

func (c *Command) Steal(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "steal"

	description := "Steal and use a Windows access token from another process"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token steal 1320\n" +
		"\t[-] Created job xBDIToajju for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[-] Results job xBDIToajju for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n\n" +
		"\t[+] Successfully stole token from PID 1320 for user ACME\\Administrator with LogonID 0x39DF3C"
	usage := "token steal PID"
	notes := "The steal command obtains a handle to a remote process’ access token, duplicates it through the " +
		"DuplicateTokenEx Windows API, and subsequently uses it to perform future post-exploitation commands.\n" +
		"\tThere is an unregistered steal_token command alias that can be use from the agent root menu prompt\n" +
		"\tReferences:\n" +
		"\t\t- https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. token, 1. steal, 2. PID
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires one argument\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	switch strings.ToLower(args[2]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level: messages.Info,
			Message: fmt.Sprintf("'%s %s' command help\n\n"+
				"Description:\n\t%s\n"+
				"Usage:\n\t%s\n"+
				"Example:\n\t%s\n"+
				"Notes:\n\t%s",
				c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
			Time: time.Now().UTC(),
		}
		return
	}

	_, err := strconv.Atoi(args[2])
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error converting '%s' to an integer: %s", args[2], err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	msg := agentAPI.Token(id, args)
	response.Message = &msg
	return
}

func (c *Command) Whoami(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "whoami"

	description := "Return information about the process and thread Windows access tokens"
	example := ""
	notes := "The whoami command leverages the Windows GetTokenInformaion API call to return information about " +
		"both the process and thread Windows access token. This information includes:\n\n" +
		"\t\t- Username\n" +
		"\t\t- Token ID\n" +
		"\t\t- Logon ID\n" +
		"\t\t- Privilege Count\n" +
		"\t\t- Group Count\n" +
		"\t\t- Token Type\n" +
		"\t\t- Token Impersonation Level\n" +
		"\t\t- Integrity Level\n\n" +
		"\tReferences:\n" +
		"\t\t- https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation"
	usage := "token whoami"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	// 0. token, 1. whoami, 2. -h
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level: messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\n"+
					"Description:\n\t%s\n"+
					"Usage:\n\t%s\n"+
					"Example:\n\t%s\n"+
					"Notes:\n\t%s",
					c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time: time.Now().UTC(),
			}
			return
		}
	}
	msg := agentAPI.Token(id, args)
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
