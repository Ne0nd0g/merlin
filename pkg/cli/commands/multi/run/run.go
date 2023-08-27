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

package run

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
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
	moduleMemory "github.com/Ne0nd0g/merlin/pkg/cli/module/memory"
)

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string                  // name is the name of the command
	help   map[menu.Menu]help.Help // help is the Help structure for the command
	menus  []menu.Menu             // menu is the Menu the command can be used in
	native bool                    // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS                   // os is the supported operating system the Agent command can be executed on
}

// NewCommand is a factory that builds and returns a Command structure that implements the Command interface
func NewCommand() *Command {
	var cmd Command
	cmd.name = "run"
	cmd.menus = []menu.Menu{menu.AGENT, menu.LISTENERSETUP, menu.MODULE}
	cmd.os = os.ALL

	cmd.help = make(map[menu.Menu]help.Help)

	// Help for the Agent menu
	agentDescription := "Execute a program and return output"
	agentUsage := "run program [arguments]"
	agentExample := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run ping 8.8.8.8\n" +
		"\t[-]Created job DTBnkIfnus for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+]Results for job DTBnkIfnus\n\n" +
		"\tPinging 8.8.8.8 with 32 bytes of data:\n" +
		"\tReply from 8.8.8.8: bytes=32 time=23ms TTL=54\n" +
		"\tReply from 8.8.8.8: bytes=32 time=368ms TTL=54\n" +
		"\tReply from 8.8.8.8: bytes=32 time=26ms TTL=54\n" +
		"\tReply from 8.8.8.8: bytes=32 time=171ms TTL=54\n\n" +
		"\tPing statistics for 8.8.8.8:\n" +
		"\t    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n" +
		"\tApproximate round trip times in milli-seconds:\n" +
		"\t    Minimum = 23ms, Maximum = 368ms, Average = 147ms\n\n" +
		"\tExample running 'ver' without cmd.exe:\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run ver\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»" +
		"\t[-]Created job iOMPERNYGT for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+]Results for job iOMPERNYGT\n" +
		"\texec: \"ver\": executable file not found in %PATH%\n\n" +
		"\tExample running 'ver' with cmd.exe:\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run cmd.exe /c ver\n" +
		"\tMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» " +
		"\t[-]Created job IxVXgyIkhS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t[+]Results for job IxVXgyIkhS\n\n" +
		"\tMicrosoft Windows [Version 10.0.16299.64]"
	agentNotes := "The run command is used to task the agent to run a program on the host and return STDOUT/STDERR. " +
		"When issuing a command to an agent from the server, the agent will execute the provided binary file for the " +
		"program you specified and also pass along any arguments you provide. It is important to note that program must " +
		"be in the path. This allows an operator to specify and use a shell (e.g.,. cmd.exe, powershell.exe, or /bin/bash) " +
		"or to execute the program directly WITHOUT a shell. For instance, 'ping.exe' is typically in the host’s %PATH% " +
		"variable on Windows and works without specifying 'cmd.exe'. However, the 'ver' command is not an executable in the " +
		"%PATH% and therefore must be run from 'cmd.exe'. Use the 'shell' command if you want to use the operating system’s " +
		"default shell directly."
	cmd.help[menu.AGENT] = help.NewHelp(agentDescription, agentExample, agentNotes, agentUsage)

	// Help for the Listener menu
	listenerDescription := "Create and start the listener on the server"
	listenerUsage := "run"
	listenerExample := "Merlin[listeners]» use https\n" +
		"\tMerlin[listeners][https]» run\n\n" +
		"\t[!] Insecure publicly distributed Merlin x.509 testing certificate in use for https server on 127.0.0.1:443\n" +
		"\tAdditional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates\n\n" +
		"\t[+] Default listener was created with an ID of: 632db67c-7045-462f-bf09-aea90272aed5\n" +
		"\tMerlin[listeners][Default]»\n[+] Started HTTPS listener on 127.0.0.1:443\n" +
		"\tMerlin[listeners][Default]»"
	listenerNotes := ""
	cmd.help[menu.LISTENERSETUP] = help.NewHelp(listenerDescription, listenerExample, listenerNotes, listenerUsage)

	// Help for the Module menu
	moduleDescription := "Execute the module"
	moduleExample := "Merlin[module][Invoke-Mimikatz]» run\n" +
		"\tMerlin[module][Invoke-Mimikatz]» [-]Created job iReycchrck for agent ebf1b1d2-44d5-4f85-86f5-cae112600870\n" +
		"\t[+]Results for job iReycchrck\n" +
		"\t[+]\n" +
		"\t  .#####.   mimikatz 2.1 (x64) built on Nov 10 2016 15:31:14\n" +
		"\t .## ^ ##.  \"A La Vie, A L'Amour\"\n" +
		"\t ## / \\ ##  /* * *\n" +
		"\t ## \\ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n" +
		"\t '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)\n" +
		"\t  '#####'                                     with 20 modules * * */\n" +
		"\t<snip>\n" +
		"\tMerlin[module][Invoke-Mimikatz]»"
	moduleNotes := ""
	moduleUsage := "run"
	cmd.help[menu.MODULE] = help.NewHelp(moduleDescription, moduleExample, moduleNotes, moduleUsage)

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

	switch m {
	case menu.AGENT:
		return c.DoAgent(id, arguments)
	case menu.LISTENERSETUP:
		return c.DoListener(id, arguments)
	case menu.MODULE:
		return c.DoModule(id, arguments)
	default:
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is an unhandled menu option for the %s command", m, c.name),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
}

// DoAgent processes the command for the Agent menu
func (c *Command) DoAgent(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args, err := shellwords.Parse(arguments)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Error:   true,
			Message: fmt.Sprintf("there was an error parsing the arguments: %s", err),
			Time:    time.Now().UTC(),
		}
		err = nil
		return
	}

	h := c.help[menu.AGENT]
	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command requires at least one argument\nUsage: %s", c, h.Usage()),
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
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}
	msg := agentAPI.CMD(id, args)
	response.Message = &msg
	return
}

// DoListener processes the command for the Listener menu
func (c *Command) DoListener(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		h := c.help[menu.LISTENERSETUP]
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
		default:
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("Usage: %s", h),
				Time:    time.Now().UTC(),
			}
		}
		return
	}

	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		msg := messages.ErrorMessage(fmt.Sprintf("there was an error getting the listener for ID %s: %s", id, err))
		response.Message = &msg
		return
	}

	// Validate the listener options contains a "Name" key
	if _, ok := listener.Options()["Name"]; !ok {
		msg := messages.ErrorMessage(fmt.Sprintf("the listener options for ID %s does not contain a 'Name' key", id))
		response.Message = &msg
		return
	}

	// Use the API to create a new listener
	msg, serverID := listenerAPI.NewListener(listener.Options())
	if msg.Error {
		response.Message = &msg
		return
	}

	// Finish building the Response
	response.Listener = serverID
	response.Message = &msg
	response.Menu = menu.LISTENER
	response.Prompt = fmt.Sprintf("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m%s\033[31m]»\033[0m ", serverID)

	// Use the API to start the listener
	msg = listenerAPI.Start(serverID)

	// Remove it from the repo
	repo.Remove(id)
	return
}

// DoModule processes the command for the Module menu
func (c *Command) DoModule(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		h := c.help[menu.MODULE]
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	// Get options from the local repository
	repo := moduleMemory.NewRepository()
	m, err := repo.Get(id)
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("pkg/cli/commands/info.DoModule(): there was an error getting module ID %s from the repository", err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		err = nil
		return
	}
	returnMessages := moduleAPI.RunModule(m)
	if len(returnMessages) > 1 {
		for _, message := range returnMessages {
			core.MessageChannel <- message
		}
	} else {
		response.Message = &returnMessages[0]
	}
	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	_, ok := c.help[m]
	if !ok {
		return help.NewHelp(fmt.Sprintf("the 'info' command's Help structure does not exist for the %s menu", m), "", "", "")
	}
	return c.help[m]
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
