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

// CheckIn returns the Command structure for the CheckIn command
func CheckIn() (cmd Command) {
	name := "checkin"
	var help Help
	help.Description = "Force the agent to check in and send back an AgentInfo message."
	help.Usage = "checkin <agent ID>"
	help.Example = "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» checkin\n"
	help.Example += "[-] Created job WtmpAyIdhq for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-05-17T12:12:05Z\n"
	help.Example += "[-] Results of job WtmpAyIdhq for agent c1090dbc-f2f7-4d90-a241-86e0c0217786 at 2023-05-17T12:12:20Z\n"
	help.Example += "\tConfiguration data received for Agent c1090dbc-f2f7-4d90-a241-86e0c0217786 and updated. Issue the \"info\" command to view it."
	help.Notes = "This command is typically used for peer-to-peer agents that have been configured with a negative sleep value to prevent them from communicating until they have a message to send back to the server."
	cmd = NewCommand(name, agents.CheckIn, help, AGENT, true, ALL)
	return
}
