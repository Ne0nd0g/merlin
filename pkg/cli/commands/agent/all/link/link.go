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

package link

import (
	// Standard
	"fmt"
	"net"
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
	cmd.name = "link"
	cmd.menus = []menu.Menu{menu.AGENT}
	cmd.os = os.ALL
	description := "Establish a connection link with a peer-to-peer Agent"
	// Style guide for usage https://developers.google.com/style/code-syntax
	usage := "link {add|list|remove|refresh|tcp|udp|smb} address"
	example := "link list"
	notes := "Use '-h' after the subcommand to get more information"
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
	return readline.PcItem("link",
		readline.PcItem("add"),
		readline.PcItem("list"),
		readline.PcItem("remove"),
		readline.PcItem("refresh"),
		readline.PcItem("tcp",
			readline.PcItem("127.0.0.1:7777"),
		),
		readline.PcItem("udp",
			readline.PcItem("127.0.0.1:7777"),
		),
		readline.PcItem("smb",
			readline.PcItem(".",
				// TODO Replace with names of known SMB listener pipes
				readline.PcItem("merlinpipe"),
			),
		),
	)
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
	case "add":
		return c.Add(id, arguments)
	case "list":
		return c.List(id, arguments)
	case "refresh":
		return c.Refresh(id, arguments)
	case "remove":
		return c.Remove(id, arguments)
	case "smb":
		return c.SMB(id, arguments)
	case "tcp":
		return c.TCP(id, arguments)
	case "udp":
		return c.UDP(id, arguments)
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, c.help.Description(), c.help.Usage(), c.help.Example(), c.help.Notes()),
			Time:    time.Now().UTC(),
		}
		return
	default:
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: c.help.Usage(),
			Time:    time.Now().UTC(),
			Error:   false,
		}
		return
	}
}

// Add instructs the server to add a child Agent to the calling Agent's peer-to-peer list
func (c *Command) Add(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "add"

	description := "Manually add a peer-to-peer child Agent link by UUID on the server"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link add afe6e797-f06f-449c-9f7a-2ba3df50c1b8\n" +
		"\t[+] Successfully added child agent afe6e797-f06f-449c-9f7a-2ba3df50c1b8 link to parent agent c1090dbc-f2f7-4d90-a241-86e0c0217786"
	notes := "This is useful if the Server was restarted and does not know about the peer-to-peer parent/child " +
		"relationship. This command does not add or create a peer-to-peer link on the Agent itself."
	usage := "link add childAgentID"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. link, 1. add, 2. UUID
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires at least one argument\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	switch strings.ToLower(args[2]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Validate argument is a valid UUID
	_, err := uuid.FromString(args[2])
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error converting %s to a UUID: %s", args[2], err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	msg := agentAPI.LinkAgent(id, args)
	response.Message = &msg
	return
}

// List instructs the Agent to return a list of peer-to-peer Agents
func (c *Command) List(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "list"

	description := "Instruct the Agent to return a list of its peer-to-peer links"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link list\n" +
		"\t[-] Created job SisWtXgSke for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:06:22Z\n" +
		"\t[-] Results of job SisWtXgSke for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:06:40Z\n" +
		"\t[+] Peer-to-Peer Links (2)\n" +
		"\t0. tcp-bind:c426dce8-ffd9-42cc-8393-8885b731cc3b9:127.0.0.1:7777\n" +
		"\t1. udp-bind:2f915108-0dd2-40fe-bf8b-8503b840a6ee:127.0.0.1:7777"
	notes := ""
	usage := "link list"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	msg := agentAPI.LinkAgent(id, args)
	response.Message = &msg
	return
}

func (c *Command) Remove(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "remove"

	description := "Instruct the Agent to remove a child peer-to-peer Agent link"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link remove c426dce8-ffd9-42cc-8393-8885b731cc3b\n" +
		"\t[-] Created job JgjPdlbVTD for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:23:08Z\n" +
		"\t[-] Results of job JgjPdlbVTD for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:23:26Z\n" +
		"\t[+] Successfully removed P2P link for c426dce8-ffd9-42cc-8393-8885b731cc3b\n"
	notes := "This is useful if a child peer-to-peer Agent dies but did not gracefully close the connection " +
		"with the parent. This is more common with reverse peer-to-peer Agents"
	usage := "link remove childAgentID"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. link, 1. remove, 2. UUID
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires at least one argument\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	switch strings.ToLower(args[2]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Validate argument is a valid UUID
	_, err := uuid.FromString(args[2])
	if err != nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("there was an error converting %s to a UUID: %s", args[2], err),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	msg := agentAPI.LinkAgent(id, args)
	response.Message = &msg
	return
}

func (c *Command) Refresh(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "refresh"

	description := "Instruct the Agent to update the server with a full list of child peer-to-peer Agents"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link refresh\n" +
		"\t[-] Created job jSWPVmORJq for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:32:21Z\n" +
		"\t[-] Results of job jSWPVmORJq for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:32:42Z\n" +
		"\t[+] Created upstream delegate messages for:\n" +
		"\tPeer-to-Peer Links (1)\n" +
		"\t0. tcp-bind:c426dce8-ffd9-42cc-8393-8885b731cc3b:127.0.0.1:7777\n"
	notes := "This is useful if the server is restarted and is not tracking the parent/child relationships or " +
		"when a reverse Agent has negative sleep"
	usage := "link refresh"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. link, 1. refresh, 2. -h
	// Check for help first
	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}
	msg := agentAPI.LinkAgent(id, args)
	response.Message = &msg
	return
}

func (c *Command) TCP(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "tcp"

	description := "Link to a child peer-to-peer bind TCP Agent"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link tcp 127.0.0.1:7777 \n" +
		"\t[-] Created job fpXxQBSMrN for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T11:53:32Z\n" +
		"\t[-] Results of job fpXxQBSMrN for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T11:53:54Z\n" +
		"\t[+] Successfully connected to tcp-bind Agent c426dce8-ffd9-42cc-8393-8885b731cc3b at 127.0.0.1:7777\n" +
		"\t[+] New authenticated agent checkin for c426dce8-ffd9-42cc-8393-8885b731cc3b at 2023-07-22T11:54:29Z"
	notes := ""
	usage := "link tcp interface:port"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. link, 1. tcp, 2. interface:port
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires at least one argument\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	switch strings.ToLower(args[2]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Client side validate interface and port
	addr := strings.Split(args[2], ":")
	if len(addr) != 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is not a valid IP address and port:\n%s", args[2], h.Usage()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	if net.ParseIP(addr[0]) == nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is not a valid IP address", addr[0]),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}

	msg := agentAPI.LinkAgent(id, args)
	response.Message = &msg
	return
}

func (c *Command) UDP(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "udp"

	description := "Link to a child peer-to-peer bind UDP Agent"
	example := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» link udp 127.0.0.1:7777 \n" +
		"\t[-] Created job GflFUgVCwS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:03:47Z\n" +
		"\t[-] Results of job GflFUgVCwS for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-07-22T12:04:00Z\n" +
		"\t[+] Successfully connected to udp-bind Agent 2f915108-0dd2-40fe-bf8b-8503b840a6ee at 127.0.0.1:7777\n" +
		"\t[+] New authenticated agent checkin for 2f915108-0dd2-40fe-bf8b-8503b840a6ee at 2023-07-22T12:04:31Z\n"
	notes := ""
	usage := "link udp interface:port"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	// 0. link, 1. udp, 2. interface:port
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires at least one argument\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	switch strings.ToLower(args[2]) {
	case "help", "-h", "--help", "?", "/?":
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
			Time:    time.Now().UTC(),
		}
		return
	}

	// Client side validate interface and port
	addr := strings.Split(args[2], ":")
	if len(addr) != 2 {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is not a valid IP address and port:\n%s", args[2], h.Usage()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}
	if net.ParseIP(addr[0]) == nil {
		response.Message = &messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("'%s' is not a valid IP address", addr[0]),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}

	msg := agentAPI.LinkAgent(id, args)
	response.Message = &msg
	return
}

func (c *Command) SMB(id uuid.UUID, arguments string) (response commands.Response) {
	sub := "smb"
	description := "Link to a child peer-to-peer bind SMB Agent"
	example := "Merlin[agent][eb2a4636-cd93-4818-a844-87340d4a1c6a]» link smb . merlinpipe \n" +
		"\t[-] Created job ykIsVgNQDO for agent eb2a4636-cd93-4818-a844-87340d4a1c6a at 2023-07-22T13:09:57Z\n" +
		"\t[-] Results of job ykIsVgNQDO for agent eb2a4636-cd93-4818-a844-87340d4a1c6a at 2023-07-22T13:10:15Z\n" +
		"\t[+] Successfully connected to smb-bind Agent 206babc3-34fe-49fd-a018-9d4d1026bbec at \\\\.\\pipe\\merlinpipe\n" +
		"\t[+] New authenticated agent checkin for 206babc3-34fe-49fd-a018-9d4d1026bbec at 2023-07-22T13:10:47Z\n\n" +
		"\tMerlin[agent][1156a10c-9bc3-4d27-ad9f-5723be452cc6]» link smb 192.168.79.128 merlinpipe\n" +
		"\t[-] Created job NsFduoHEGW for agent 1156a10c-9bc3-4d27-ad9f-5723be452cc6 at 2023-07-22T13:14:35Z\n" +
		"\t[-] Results of job NsFduoHEGW for agent 1156a10c-9bc3-4d27-ad9f-5723be452cc6 at 2023-07-22T13:14:59Z\n" +
		"\t[+] Successfully connected to smb-bind Agent 295b0dab-af06-480c-b43b-eb81be87aa0b at \\\\192.168.79.128\\pipe\\merlinpipe\n" +
		"\t[+] New authenticated agent checkin for 295b0dab-af06-480c-b43b-eb81be87aa0b at 2023-07-22T13:15:34Z"
	notes := "The ADDRESS can be a '.' for the localhost, an IP address, or a DNS hostname. The parent Agent " +
		"must be running on a Windows host."
	usage := "link smb address pipeName"
	h := help.NewHelp(description, example, notes, usage)

	// Parse the arguments
	args := strings.Split(arguments, " ")

	if len(args) > 2 {
		switch strings.ToLower(args[2]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = &messages.UserMessage{
				Level:   messages.Info,
				Message: fmt.Sprintf("'%s %s' command help\n\nDescription:\n\t%s\nUsage:\n\t%s\nExample:\n\t%s\nNotes:\n\t%s", c, sub, h.Description(), h.Usage(), h.Example(), h.Notes()),
				Time:    time.Now().UTC(),
			}
			return
		}
	}

	// 0. link, 1. smb, 2. address, 3. pipename
	if len(args) < 3 {
		response.Message = &messages.UserMessage{
			Level:   messages.Info,
			Message: fmt.Sprintf("'%s %s' command requires two arguments\n%s", c, sub, h.Usage()),
			Time:    time.Now().UTC(),
		}
		return
	}

	msg := agentAPI.LinkAgent(id, args)
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
