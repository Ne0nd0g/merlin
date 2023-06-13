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

// Clear returns the Command structure for the clear command
func Clear() (cmd Command) {
	name := "clear"
	var help Help
	help.Description = "Cancel, or clear, all jobs in the current Agent's queue that have not already been sent to the agent."
	help.Usage = "clear"
	help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» clear\n[+] jobs cleared for agent c1090dbc-f2f7-4d90-a241-86e0c0217786"
	help.Notes = "This command will only clear jobs for the current agent."
	cmd = NewCommand(name, nil, help, AGENT, true, ALL)
	return
}
