// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2023  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

// Package jobs holds the structures for Agent jobs
package jobs

import (
	// Standard
	"encoding/gob"
	"fmt"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/core"
)

// init registers message types with gob that are an interface for Base.Payload
func init() {
	gob.Register([]Job{})
	gob.Register(Command{})
	gob.Register(Shellcode{})
	gob.Register(FileTransfer{})
	gob.Register(Results{})
	gob.Register(Socks{})
}

const (
	// CREATED is used to denote that job has been created
	CREATED = 1
	// SENT is used to denote that the job has been sent to the Agent
	SENT = 2
	// RETURNED is for when a chunk has been returned but the job hasn't finished running
	RETURNED = 3
	// COMPLETE is used to denote that the job has finished running and the Agent has sent back the results
	COMPLETE = 4
	// CANCELED is used to denoted jobs that were cancelled with the "clear" command
	CANCELED = 5
	// ACTIVE is used with SOCKS connections to show the connection between the SOCKS client and server is active
	ACTIVE = 6

	// To Agent

	// CMD is used to send CmdPayload messages
	CMD = 10 // CmdPayload
	// CONTROL is used to send AgentControl messages
	CONTROL = 11 // AgentControl
	// SHELLCODE is used to send shellcode messages
	SHELLCODE = 12 // Shellcode
	// NATIVE is used to send NativeCmd messages
	NATIVE = 13 // NativeCmd
	// FILETRANSFER is used to send FileTransfer messages for upload/download operations
	FILETRANSFER = 14 // FileTransfer
	// OK is used to signify that there is nothing to do, or to idle
	OK = 15 // ServerOK
	// MODULE is used to send Module messages
	MODULE = 16 // Module
	// SOCKS is used for SOCKS5 traffic between the server and agent
	SOCKS = 17 // SOCKS

	// From Agent

	// RESULT is used by the Agent to return a result message
	RESULT = 20
	// AGENTINFO is used by the Agent to return information about its configuration
	AGENTINFO = 21
)

// Job is used to task an agent to run a command
type Job struct {
	AgentID uuid.UUID   // ID of the agent the job belong to
	ID      string      // Unique identifier for each job
	Token   uuid.UUID   // A unique token for each task that acts like a CSRF token to prevent multiple job messages
	Type    int         // The type of job it is (e.g., FileTransfer
	Payload interface{} // Embedded messages of various types
}

// Command is the structure to send a task for the agent to execute
type Command struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// Shellcode is a JSON payload containing shellcode and the method for execution
type Shellcode struct {
	Method string `json:"method"`
	Bytes  string `json:"bytes"`         // Base64 string of shellcode bytes
	PID    uint32 `json:"pid,omitempty"` // Process ID for remote injection
}

// FileTransfer is the JSON payload to transfer files between the server and agent
type FileTransfer struct {
	FileLocation string `json:"dest"`
	FileBlob     string `json:"blob"`
	IsDownload   bool   `json:"download"`
}

// Results is a JSON payload that contains the results of an executed command from an agent
type Results struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Socks is used to transfer data from a SOCKS client through the server to the agent and back
type Socks struct {
	ID    uuid.UUID `json:"id"`
	Index int       `json:"index"`
	Data  []byte    `json:"data"`
	Close bool      `json:"close"`
}

// Info is a structure for holding data for single task assigned to a single agent
type Info struct {
	id        string    // id is a unique identifier for the job
	agentID   uuid.UUID // ID of the agent the job belong to
	jobType   string    // Type of job
	token     uuid.UUID // A unique token for each task that acts like a CSRF token to prevent multiple job messages
	status    int       // Use JOB_ constants
	chunk     int       // The chunk number
	created   time.Time // Time the job was created
	sent      time.Time // Time the job was sent to the agent
	completed time.Time // Time the job finished
	command   string    // The actual command
}

// NewInfo is a factor to return an Info structure used to track a job's status
func NewInfo(agent uuid.UUID, jobType string, cmd string) Info {
	info := Info{
		id:      core.RandStringBytesMaskImprSrc(10),
		agentID: agent,
		jobType: jobType,
		token:   uuid.NewV4(),
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
func (i *Info) Status() int {
	return i.status
}

// Token returns the Job's token
func (i *Info) Token() uuid.UUID {
	return i.token
}

// String returns the text representation of a message constant
func String(jobType int) string {
	switch jobType {
	case CMD:
		return "Command"
	case CONTROL:
		return "AgentControl"
	case SHELLCODE:
		return "Shellcode"
	case NATIVE:
		return "Native"
	case FILETRANSFER:
		return "FileTransfer"
	case OK:
		return "ServerOK"
	case MODULE:
		return "Module"
	case RESULT:
		return "Result"
	case AGENTINFO:
		return "AgentInfo"
	case SOCKS:
		return "SOCKS5"
	default:
		return fmt.Sprintf("Invalid job type: %d", jobType)
	}
}
