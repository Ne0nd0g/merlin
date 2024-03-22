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

// Package jobs holds the structures for Agent jobs
package jobs

import (
	// Standard
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
)

type Status int

const (
	UNDEFINED Status = iota
	// CREATED is used to denote that job has been created
	CREATED
	// SENT is used to denote that the job has been sent to the Agent
	SENT
	// RETURNED is for when a chunk has been returned but the job hasn't finished running
	RETURNED
	// COMPLETE is used to denote that the job has finished running and the Agent has sent back the results
	COMPLETE
	// CANCELED is used to denoted jobs that were cancelled with the "clear" command
	CANCELED
	// ACTIVE is used with SOCKS connections to show the connection between the SOCKS client and server is active
	ACTIVE
)

// Info is a structure for holding data for single task assigned to a single agent
type Info struct {
	id        string    // id is a unique identifier for the job
	agentID   uuid.UUID // ID of the agent the job belong to
	jobType   string    // Type of job
	token     uuid.UUID // A unique token for each task that acts like a CSRF token to prevent multiple job messages
	status    Status    // Use JOB_ constants
	chunk     int       // The chunk number
	created   time.Time // Time the job was created
	sent      time.Time // Time the job was sent to the agent
	completed time.Time // Time the job finished
	command   string    // The actual command
}

// NewInfo is a factory to return an Info structure used to track a job's status
func NewInfo(agent uuid.UUID, jobType string, cmd string) Info {
	info := Info{
		id:      core.RandStringBytesMaskImprSrc(10),
		agentID: agent,
		jobType: jobType,
		token:   uuid.New(),
		status:  CREATED,
		created: time.Now().UTC(),
		command: cmd,
	}
	return info
}

func NewInfoWithID(agent uuid.UUID, jobType string, cmd string, id string, token uuid.UUID) Info {
	info := Info{
		id:      id,
		agentID: agent,
		jobType: jobType,
		token:   token,
		status:  CREATED,
		created: time.Now().UTC(),
		command: cmd,
	}
	return info
}

// Active set's the Job Info status to "active"
func (i *Info) Active() {
	i.status = ACTIVE
}

// AgentID returns the associated Agent's ID
func (i *Info) AgentID() uuid.UUID {
	return i.agentID
}

// Cancel set's the Job Info status to "canceled"
func (i *Info) Cancel() {
	i.completed = time.Now().UTC()
	i.status = CANCELED
}

// Command returns the command associated with the Job
func (i *Info) Command() string {
	return i.command
}

// Complete set's the Job Info status to "complete"
func (i *Info) Complete() {
	i.completed = time.Now().UTC()
	i.status = COMPLETE
}

// Completed returns the time of when the Job completed
func (i *Info) Completed() time.Time {
	return i.completed
}

// Created returns the time of when the Job was created
func (i *Info) Created() time.Time {
	return i.created
}

// ID returns the Job's unique identifier
func (i *Info) ID() string {
	return i.id
}

// Send set's the Job Info status to "sent"
func (i *Info) Send() {
	i.sent = time.Now().UTC()
	i.status = SENT
}

// Sent returns the time of when the Job was sent
func (i *Info) Sent() time.Time {
	return i.sent
}

// Status returns the Job's status
func (i *Info) Status() Status {
	return i.status
}

// StatusString returns the Job's status as a string
func (i *Info) StatusString() string {
	switch i.status {
	case CREATED:
		return "Created"
	case SENT:
		return "Sent"
	case RETURNED:
		return "Returned"
	case COMPLETE:
		return "Complete"
	case CANCELED:
		return "Canceled"
	case ACTIVE:
		return "Active"
	default:
		return "Unknown"
	}
}

// Token returns the Job's token
func (i *Info) Token() uuid.UUID {
	return i.token
}

func (s Status) String() string {
	switch s {
	case CREATED:
		return "Created"
	case SENT:
		return "Sent"
	case RETURNED:
		return "Returned"
	case COMPLETE:
		return "Complete"
	case CANCELED:
		return "Canceled"
	case ACTIVE:
		return "Active"
	default:
		return "Unknown"
	}
}
