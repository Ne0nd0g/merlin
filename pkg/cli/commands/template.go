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

import "github.com/Ne0nd0g/merlin/pkg/api/agents"

// template returns the Command structure for the ?? command
func template() (cmd Command) {
	name := "template"
	var help Help
	help.Description = ""
	help.Usage = "template <arg1> <arg2>"
	help.Example = ""
	help.Notes = ""
	cmd = NewCommand(name, agents.CD, help, AGENT, true, ALL)
	return
}
