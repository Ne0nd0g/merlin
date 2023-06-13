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

// CD returns the Command structure for the cd command
func CD() (cmd Command) {
	var help Help
	help.Description = "Change the Agent's current working directory to provided file system path"
	help.Usage = "cd <path>"
	help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» cd /usr/bin\n[-]Created job evtawDqBWa for agent " +
		"a98e6175-7799-47fb-abf0-32534a9191f0 at 2019-02-27T01:03:57Z\nMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]»" +
		"\n[+]Results for job evtawDqBWa at 2019-02-27T01:03:59Z\nChanged working directory to /usr/bin"
	help.Example += "\n\nMerlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» cd /usr/bin\n" +
		"[-]Created job evtawDqBWa for agent a98e6175-7799-47fb-abf0-32534a9191f0 at 2019-02-27T01:03:57Z\n" +
		"Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [+]Results for job evtawDqBWa at 2019-02-27T01:03:59Z\n" +
		"Changed working directory to /usr/bin"
	help.Notes = "Relative paths can be used (e.g.,. ./../ or downloads\\\\Merlin). " +
		"This command uses native Go and will not execute the cd binary program found on the host operating system.\n" +
		"The \\ in a Windows directory must be escaped like C:\\\\Windows\\\\System32.\n"

	cmd = NewCommand("cd", agents.CD, help, AGENT, true, ALL)
	return
}
