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

// Comms is a structure that holds information about an Agent's communication profile
type Comms struct {
	Failed  int32  // The number of times the agent has failed to check in
	JA3     string // The ja3 signature applied to the agent's TLS client
	Kill    int64  // The epoch date and time that the agent will kill itself and quit running
	Padding int32  // The maximum amount of padding that will be appended to the Base message
	Proto   string // The protocol the agent is using to communicate with the server
	Retry   int32  // The maximum amount of times an agent will retry to check in before exiting
	Skew    int64  // The amount of skew, or jitter, used to calculate the check in time
	Wait    string // The amount of time the agent waits before trying to check in
}
