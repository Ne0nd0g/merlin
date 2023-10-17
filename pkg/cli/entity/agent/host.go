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

package agent

// Host is a structure that holds information about the Host operating system an Agent is running on
type Host struct {
	Architecture string   // The operating system architecture the agent is running on (e.g., x86 or x64)
	Name         string   // The host name the agent is running on
	Platform     string   // The platform, or operating system, the agent is running on
	IPs          []string // A list of interface IP addresses on the host where the agent is running
}
