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

package banner

import (
	merlin "github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"
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
	cmd.name = "banner"
	cmd.menus = []menu.Menu{menu.MAIN, menu.AGENT, menu.LISTENER, menu.MODULE}
	cmd.os = os.LOCAL
	cmd.help.Description = "Display the Merlin ASCII art banner"
	cmd.help.Usage = "banner"
	cmd.help.Example = ""
	return &cmd
}

func (c *Command) Completer() readline.PrefixCompleterInterface {
	return readline.PcItem(c.name)
}

func (c *Command) Description() string {
	return c.help.Description
}

func (c *Command) Do(arguments string) (message messages.UserMessage) {
	m := "\n"
	m += color.BlueString(banner.MerlinBanner1)
	m += color.BlueString("\r\n\t\t   Version: %s", merlin.Version)
	m += color.BlueString("\r\n\t\t   Build: %s\n", merlin.Build)

	message.Level = messages.Plain
	message.Message = m
	message.Time = time.Now().UTC()
	return
}

func (c *Command) DoAgent(agent uuid.UUID, arguments string) (message messages.UserMessage) {
	return c.Do(arguments)
}

func (c *Command) Menu(m menu.Menu) bool {
	for _, v := range c.menus {
		if v == m {
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
