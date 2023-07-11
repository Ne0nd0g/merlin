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

package queue

import (
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"
	"strings"
	"time"
)

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string      // name is the name of the command
	help   help.Help   // help is the Help structure for the command
	menus  []menu.Menu // menu is the Menu the command can be used in
	native bool        // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS       // os is the supported operating system the Agent command can be executed on
}

func NewCommand() *Command {
	var cmd Command
	cmd.name = "queue"
	cmd.menus = []menu.Menu{menu.MAIN}
	cmd.os = os.LOCAL
	cmd.help.Description = "Queue up commands for one, multiple, or unknown agents"
	cmd.help.Usage = "queue <agent id> <command> [args]"
	cmd.help.Example = "Queue a command for one agent:\n\n" +
		"Merlin» queue 99dbe632-984c-4c98-8f38-11535cb5d937 run ping 8.8.8.8\n" +
		"[-] Created job LumWveIkKe for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n" +
		"[-] Results job LumWveIkKe for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n\n" +
		"[+]\nPinging 8.8.8.8 with 32 bytes of data:\n" +
		"Reply from 8.8.8.8: bytes=32 time=42ms TTL=128\n" +
		"Reply from 8.8.8.8: bytes=32 time=63ms TTL=128\n" +
		"Reply from 8.8.8.8: bytes=32 time=35ms TTL=128\n" +
		"Reply from 8.8.8.8: bytes=32 time=48ms TTL=128\n\n" +
		"Ping statistics for 8.8.8.8:\n" +
		"Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n" +
		"Approximate round trip times in milli-seconds:\n" +
		"Minimum = 35ms, Maximum = 63ms, Average = 47ms\n\n\n" +
		"Queue a command for a group:\n\n" +
		"Merlin» queue EvilCorp run whoami\n\n" +
		"[-] Created job lkvozuKJLW for agent d07edfda-e119-4be2-a20f-918ab701fa3c\n\n" +
		"[-] Created job xKAgunnKTF for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n" +
		"Merlin»\n" +
		"[-] Results job xKAgunnKTF for agent 99dbe632-984c-4c98-8f38-11535cb5d937\n\n" +
		"[+] DESKTOP-H39FR21\\bob\n\n\n" +
		"[-] Results job lkvozuKJLW for agent d07edfda-e119-4be2-a20f-918ab701fa3c\n\n" +
		"[+] rastley\n\n" +
		"Queue a command for an unknown agent:\n\n" +
		"Merlin» queue c1090dbc-f2f7-4d90-a241-86e0c0217786 run whoami\n" +
		"[-] Created job rJVyZTuHkm for agent c1090dbc-f2f7-4d90-a241-86e0c0217786"
	cmd.help.Notes = "Some agent control commands such as 'sleep' can not be queued because the agent structure must exist on the server to calculate the JWT"
	return &cmd
}

func (c *Command) Completer(id uuid.UUID) (readline.PrefixCompleterInterface, error) {
	return readline.PcItem(c.name), nil
}

func (c *Command) Description() string {
	return c.help.Description
}

func (c *Command) Do(arguments string) (message messages.UserMessage) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "/?":
			message.Message = fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, c.help.Description, c.help.Usage, c.help.Example, c.help.Notes)
			message.Level = messages.Info
			message.Time = time.Now().UTC()
			return
		}
	}
	return
}

func (c *Command) DoID(agent uuid.UUID, arguments string) (message messages.UserMessage) {
	return c.Do(arguments)
}

func (c *Command) Menu(m menu.Menu) bool {
	for _, v := range c.menus {
		if v == m || v == menu.ALLMENUS {
			return true
		}
	}
	return false
}

func (c *Command) String() string {
	return c.name
}

func (c *Command) Usage() string {
	return c.help.Usage
}
