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

import (
	// Standard
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/opaque"
)

// Agent is an aggregate structure that holds information about Agent's the server is communicating with
type Agent struct {
	id            uuid.UUID      // id is the Agent's unique identifier
	alive         bool           // alive indicates if the Agent is alive or if it has been killed or instructed to exit
	authenticated bool           // Is the agent authenticated?
	build         Build          // Agent build hash and version number
	host          Host           // Structure containing information about the host the agent is running on
	process       Process        // Structure containing information about the process the agent is running in
	comms         Comms          // Structure containing information about the communication profile the agent is using
	initial       time.Time      // The first time when the agent initially checked ed
	checkin       time.Time      // The last time the agent has checked in
	linkedAgents  []uuid.UUID    // linkedAgents contains a list of first-order peer-to-peer connected agents
	listener      uuid.UUID      // The listener associated with the agent
	log           *os.File       // The log used by the agent; Contains a mutex locker and is causing problems
	secret        []byte         // secret is used to perform symmetric encryption operations
	opaque        *opaque.Server // Holds information about opaque Registration and Authentication
	note          string         // Operator notes for an agent
}

// NewAgent is a factory to create and return an Agent structure based on the provided inputs
func NewAgent(id uuid.UUID, secret []byte, opaque *opaque.Server, initial time.Time) (agent Agent, err error) {
	agent.id = id
	agent.secret = secret
	agent.opaque = opaque
	agent.initial = initial

	agent.log, err = createLogFile(id)
	if err != nil {
		return
	}

	return
}

// TODO Move this to a repository that uses flat files for now but potentially a database in the future
// createLogFile makes a new log file for the provided Agent ID for future log messages
func createLogFile(id uuid.UUID) (agentLog *os.File, err error) {
	current, err := os.Getwd()
	if err != nil {
		slog.Error(err.Error())
		return nil, fmt.Errorf("there was an error getting the current working directory: %s", err)
	}
	dir := filepath.Join(current, "data", "agents")

	// Create a directory for the new agent's files
	if _, err = os.Stat(filepath.Join(dir, id.String())); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Join(dir, id.String()), 0750)
		if err != nil {
			return nil, fmt.Errorf("pkg/agents.createLogFile(): there was an error creating a directory for agent %s: %s", id, err)
		}
		// Create the agent's log file
		agentLog, err = os.Create(filepath.Join(dir, id.String(), "log.txt")) // #nosec G304 Users can include any file they want
		if err != nil {
			return nil, fmt.Errorf("pkg/agents.createLogFile(): there was an error creating the log.txt file for agent %s: %s", id, err)
		}

		// Change the file's permissions
		err = os.Chmod(agentLog.Name(), 0600)
		if err != nil {
			return nil, fmt.Errorf("pkg/agents.createLogFile(): there was an error changing the agent's log file permissions for %s: %s", id, err)
		}
	}

	// Open agent's log file for writing
	agentLog, err = os.OpenFile(filepath.Clean(filepath.Join(dir, id.String(), "log.txt")), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("pkg/agents.createLogFile(): there was an error opening the log file for agent %s: %s", id, err)
	}
	return
}

// Alive returns true if the Agent is actively in use and false if the agent has been killed or removed
func (a *Agent) Alive() bool {
	return a.alive
}

// Authenticated checks to see if the agent has successfully completed authentication
func (a *Agent) Authenticated() bool {
	return a.authenticated
}

// SetAuthenticated updates that Agent's authenticated field, typically once authentication has completed
func (a *Agent) SetAuthenticated(authenticated bool) {
	a.authenticated = authenticated
}

// ID return's the Agent's unique ID
func (a *Agent) ID() uuid.UUID {
	return a.id
}

// Initial returns the timestamp from when the Agent was first seen
func (a *Agent) Initial() time.Time {
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

// Host returns the Agent's embedded Host entity structure
// Contains information about the host the Agent is running on such as hostname, operating system, architecture, and IP addresses
func (a *Agent) Host() Host {
	return a.host
}

// Listener returns the unique identifier of the Listener that the agent belongs to
// The associated listener determines Agent traffic encryption/encoding and delivery mechanism
func (a *Agent) Listener() uuid.UUID {
	return a.listener
}

// Secret returns the Agent's secret key, typically used to encrypt/decrypt messages
func (a *Agent) Secret() []byte {
	return a.secret
}

// SetSecret updates the Agent's secret key with the provided value
func (a *Agent) SetSecret(secret []byte) {
	a.secret = secret
}

// OPAQUE returns the Agent's embedded OPAQUE server structure
func (a *Agent) OPAQUE() *opaque.Server {
	return a.opaque
}

// ResetOPAQUE resets the Agent's embedded OPAQUE server structure to nil
func (a *Agent) ResetOPAQUE() {
	a.opaque = nil
}

// Padding returns the Agent's communication profile message padding size
func (a *Agent) Padding() int {
	return a.comms.Padding
}

// Log write the provided message to the Agent's log file
func (a *Agent) Log(message string) {
	_, err := a.log.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now().UTC().Format(time.RFC3339), message))
	if err != nil {
		slog.Error("there was an error writing to the agent's log file", "agent", a.id, "error", err)
	}
	return
}

// UpdateAlive updates the Agent's alive status to the provided value
func (a *Agent) UpdateAlive(alive bool) {
	a.alive = alive
}

// UpdateAuthenticated updates the Agent's authentication status to the provided value
func (a *Agent) UpdateAuthenticated(authenticated bool) {
	a.authenticated = authenticated
}

// UpdateBuild updates the Agent's embedded Build entity structure with the provided structure
func (a *Agent) UpdateBuild(build Build) {
	a.build = build
}

// UpdateComms updates the Agent's embedded Comms entity structure with the provided structure
func (a *Agent) UpdateComms(comms Comms) {
	a.comms = comms
}

// UpdateHost updates the Agent's embedded Host entity structure with the provided structure
func (a *Agent) UpdateHost(host Host) {
	a.host = host
}

// UpdateInitial updates the time stamp for when the Agent was first seen
func (a *Agent) UpdateInitial(initial time.Time) {
	a.initial = initial
}

// UpdateListener updates the listener ID the Agent belongs to
func (a *Agent) UpdateListener(listener uuid.UUID) {
	a.listener = listener
}

// UpdateOPAQUE updates the Agent's embedded OPAQUE server structure with the provided structure
func (a *Agent) UpdateOPAQUE(opaque *opaque.Server) {
	a.opaque = opaque
}

// UpdateProcess updates the Agent's embedded Process entity structure with the provided structure
func (a *Agent) UpdateProcess(process Process) {
	a.process = process
}

// UpdateNote update the Agent's note field with the provided message
func (a *Agent) UpdateNote(note string) {
	a.note = note
}

// UpdateStatusCheckin updates the time stamp for when the Agent last checked in
func (a *Agent) UpdateStatusCheckin(checkin time.Time) {
	a.checkin = checkin
}

// StatusCheckin returns a time stamp of when the agent last checked in
func (a *Agent) StatusCheckin() time.Time {
	return a.checkin
}

// Note returns the value of the Agent's note field
func (a *Agent) Note() string {
	return a.note
}

// Links returns a list of linked Agent IDs where this agent is the parent and the list of Agents are the children
func (a *Agent) Links() []uuid.UUID {
	return a.linkedAgents
}

// AddLink adds a new child Agent to the list of linked Agents
func (a *Agent) AddLink(link uuid.UUID) {
	a.linkedAgents = append(a.linkedAgents, link)
}

// RemoveLink deletes the child Agent link from the list of linked Agents
func (a *Agent) RemoveLink(link uuid.UUID) {
	for i, agent := range a.linkedAgents {
		if agent == link {
			a.linkedAgents = append(a.linkedAgents[:i], a.linkedAgents[i+1:]...)
		}
	}
}
