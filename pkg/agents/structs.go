/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

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

package agents

// Build is a structure that holds information about an Agent's compiled build hash and the Agent's version number
type Build struct {
	Build   string // The agent's build hash
	Version string // The agent's version number
}

// Host is a structure that holds information about the Host operating system an Agent is running on
type Host struct {
	Architecture string   // The operating system architecture the agent is running on (e.g., x86 or x64)
	Name         string   // The host name the agent is running on
	Platform     string   // The platform, or operating system, the agent is running on
	IPs          []string // A list of interface IP addresses on the host where the agent is running
}

// Process is a structure that holds information about the Process the Agent is running in/as
type Process struct {
	ID        int    // The process ID that the agent is running in
	Integrity int    // The integrity level of the process the agent is running in
	Name      string // The process name that the agent is running in
	UserGUID  string // The GUID of the user that the agent is running as
	UserName  string // The username that the agent is running as
	Domain    string // The domain the user running the process belongs to
}

// Comms is a structure that holds information about an Agent's communication profile
type Comms struct {
	Failed  int    // The number of times the agent has failed to check in
	JA3     string // The ja3 signature applied to the agent's TLS client
	Kill    int64  // The epoch date and time that the agent will kill itself and quit running
	Padding int    // The maximum amount of padding that will be appended to the Base message
	Proto   string // The protocol the agent is using to communicate with the server
	Retry   int    // The maximum amount of times an agent will retry to check in before exiting
	Skew    int64  // The amount of skew, or jitter, used to calculate the check in time
	Wait    string // The amount of time the agent waits before trying to check in
}
