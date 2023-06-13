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

// Back returns the Command structure for the ?? command
func Back() (cmd Command) {
	name := "back"
	var help Help
	help.Description = "Go up one level to the parent menu from the current child menu"
	help.Usage = "back"
	help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» back\nMerlin»"
	help.Notes = "This command is only for the local command line interface and does not interact with an API."
	cmd = NewCommand(name, nil, help, ALLMENUS, true, ALL)
	return
}
