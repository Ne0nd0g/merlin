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

// Download returns the Command structure for the download command
func Download() (cmd Command) {
	name := "download"
	var help Help
	help.Description = "Download a file from the host where the Agent is running to the Merlin server."
	help.Usage = "download <file path>"
	help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» download C:\\\\Windows\\\\hh.exe\n" +
		"Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» [-]Created job NXnhJVRUSP for agent c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"[+]Results for job NXnhJVRUSP\n" +
		"[+]Successfully downloaded file C:\\Windows\\hh.exe with a size of 17920 bytes from agent to /opt/merlin/data/agents/c1090dbc-f2f7-4d90-a241-86e0c0217786/hh.exe"
	help.Notes = "NOTE: Because \\ is used to escape a character, file paths require two (e.g., C:\\\\Windows)\n\n" +
		"Enclose file paths containing a space with quotation marks (e.g.,. \"C:\\\\Windows\\\\Program Files\\\\\")\n" +
		"The file will be automatically saved in a folder with a name of the agent’s identifier in the data/agents/ directory."
	cmd = NewCommand(name, agents.Download, help, AGENT, true, ALL)
	return
}
