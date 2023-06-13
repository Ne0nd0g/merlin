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

package commands

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string // name is the name of the command
	api    API    // api is the API used to execute the command
	help   Help   // help is the Help structure for the command
	menu   Menu   // menu is the Menu the command can be used in
	native bool   // native is true if the command is executed by an Agent using only Golang native code
	os     OS     // os is the supported operating system the Agent command can be executed on
}

// NewCommand returns a new Command structure
func NewCommand(name string, api API, help Help, menu Menu, native bool, os OS) (cmd Command) {
	cmd.name = name
	cmd.os = os
	cmd.api = api
	cmd.native = native
	cmd.help = help
	return
}

func (c *Command) String() string {
	return c.name
}
