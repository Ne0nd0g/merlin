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

// Connect returns the Command structure for the connect command
func Connect() (cmd Command) {
	name := "connect"
	var help Help
	help.Description = "Instruct the Agent to connect to provided address."
	help.Usage = "connect <address>"
	help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» connect 127.0.0.1:7779\n" +
		"[-] Created job dbIhJAzPuh for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-05-17T12:58:02Z\n" +
		"[-] Results of job dbIhJAzPuh for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-05-17T12:58:14Z\n" +
		"\t\tConfiguration data received for Agent c1090dbc-f2f7-4d90-a241-86e0c0217786 and updated. Issue the \"info\" command to view it."
	help.Notes = "WARNING: If an invalid address is provided, and the job is issued, there is no way to recover the Agent.\n\n" +
		"For HTTP based Agents, the address should be a URL like https://<ip>:<port>.\n" +
		"For TCP/UDP Agents, the address should be an IP address and port like 192.168.1.100:7777.\n" +
		"For SMB Agents, the address should be the full UNC path like \\\\\\\\127.0.0.1\\\\pipe\\\\merlinpipe\n\n" +
		"Primary use case is for child peer-to-peer Agents to connect to a different Parent Agent.\n\n" +
		"For BIND Agents, the child peer-to-peer Agent will re-bind to the provided address.\n" +
		"For REVERSE Agents, the child peer-to-peer Agent will connect to the provided address.\n" +
		"For HTTP Agents, the address can be a different listener on the current server or a completely different server all together\n\n" +
		"If the Agent connects to a different server, the job will never be completed."
	cmd = NewCommand(name, agents.Connect, help, AGENT, true, ALL)
	return
}
