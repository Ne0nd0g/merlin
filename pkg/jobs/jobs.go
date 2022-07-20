// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

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

package jobs

// TODO Does it makes sense to move this under pkg/agents/jobs?

import (
	// Standard
	"encoding/gob"
	"fmt"
	// 3rd Party
	uuid "github.com/satori/go.uuid"
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
