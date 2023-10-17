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

import (
	uuid "github.com/satori/go.uuid"
)

type Agent struct {
	id            uuid.UUID // id is the Agent's unique identifier
	alive         bool      // alive indicates if the Agent is alive or if it has been killed or instructed to exit
	authenticated bool      // Is the agent authenticated?
	build         Build     // Agent build hash and version number
	host          Host      // Structure containing information about the host the agent is running on
	process       Process   // Structure containing information about the process the agent is running in
	comms         Comms     // Structure containing information about the communication profile the agent is using
	initial       string    // The first time when the agent initially checked ed
	checkin       string    // The last time the agent has checked in
	linkedAgents  []string  // linkedAgents contains a list of first-order peer-to-peer connected agents
	listener      string    // The listener associated with the agent
	note          string    // Operator notes for an agent
	status        string    // Status of the agent (e.g., active, delayed, dead, etc.)
	groups        []string  // Groups the agent is a member of
}

func NewAgent(id uuid.UUID, alive bool, authenticated bool, build Build, host Host, process Process, comms Comms, initial string, checkin string, linkedAgents []string, listener string, note string, status string, groups []string) *Agent {
	return &Agent{
		id:            id,
		alive:         alive,
		authenticated: authenticated,
		build:         build,
		host:          host,
		process:       process,
		comms:         comms,
		initial:       initial,
		checkin:       checkin,
		linkedAgents:  linkedAgents,
		listener:      listener,
		note:          note,
		status:        status,
		groups:        groups,
	}
}

// Alive returns true if the Agent is actively in use and false if the agent has been killed or removed
func (a *Agent) Alive() bool {
	return a.alive
}

// Authenticated checks to see if the agent has successfully completed authentication
func (a *Agent) Authenticated() bool {
	return a.authenticated
}

// ID return's the Agent's unique ID
func (a *Agent) ID() uuid.UUID {
	return a.id
}

// Initial returns the timestamp from when the Agent was first seen
func (a *Agent) Initial() string {
	return a.initial
}

// Build returns the Agent's embedded Build entity structure
// Contains the agent's build and version number
func (a *Agent) Build() Build {
	return a.build
}

// Comms returns the Agent's embedded Comms entity structure
// Contains things like kill date, message padding size, transport protocol, skew, and sleep time
func (a *Agent) Comms() Comms {
	return a.comms
}

// Process returns the Agent's embedded Process entity structure
// Contains information about the process the Agent is running in/as such as process ID, name, username, domain, and integrity level
func (a *Agent) Process() Process {
	return a.process
}

// Groups returns a list of groups the Agent is a member of
func (a *Agent) Groups() []string {
	return a.groups
}

// Host returns the Agent's embedded Host entity structure
// Contains information about the host the Agent is running on such as hostname, operating system, architecture, and IP addresses
func (a *Agent) Host() Host {
	return a.host
}

// Links return a list of linked Agent IDs where this agent is the parent, and the list of Agents is the children
func (a *Agent) Links() []string {
	return a.linkedAgents
}

// Listener returns the unique identifier of the Listener that the agent belongs to
// The associated listener determines Agent traffic encryption/encoding and delivery mechanism
func (a *Agent) Listener() string {
	return a.listener
}

// Padding returns the Agent's communication profile message padding size
func (a *Agent) Padding() int32 {
	return a.comms.Padding
}

// Status returns the Agent's status
func (a *Agent) Status() string {
	return a.status
}

// StatusCheckin returns a time stamp of when the agent last checked in
func (a *Agent) StatusCheckin() string {
	return a.checkin
}

// Note returns the value of the Agent's note field
func (a *Agent) Note() string {
	return a.note
}
