// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package mythic

import uuid "github.com/satori/go.uuid"

const (
	CHECKIN        = "checkin"
	TASKING        = "get_tasking"
	RESPONSE       = "post_response"
	STATUS_SUCCESS = "success"
	STATUS_ERROR   = "error"
)

// CheckIn is the initial structure sent to Mythic
type CheckIn struct {
	Action        string `json:"action"`                    // "action": "checkin", // required
	IP            string `json:"ip"`                        // "ip": "127.0.0.1", // internal ip address - required
	OS            string `json:"os"`                        // "os": "macOS 10.15", // os version - required
	User          string `json:"user"`                      // "user": "its-a-feature", // username of current user - required
	Host          string `json:"host"`                      // "host": "spooky.local", // hostname of the computer - required
	PID           string `json:"pid"`                       // "pid": 4444, // pid of the current process - required
	PayloadID     string `json:"uuid"`                      // "uuid": "payload uuid", //uuid of the payload - required
	Arch          string `json:"architecture,omitempty"`    //  "architecture": "x64", // platform arch - optional
	Domain        string `json:"domain,omitempty"`          // "domain": "test", // domain of the host - optional
	Integrity     int    `json:"integrity_level,omitempty"` // "integrity_level": 3, // integrity level of the process - optional
	ExternalIP    string `json:"external_ip,omitempty"`     // "external_ip": "8.8.8.8", // external ip if known - optional
	EncryptionKey string `json:"encryption_key,omitempty"`  // "encryption_key": "base64 of key", // encryption key - optional
	DecryptionKey string `json:"decryption_key,omitempty"`  //  "decryption_key": "base64 of key", // decryption key - optional
}

// Response is the message structure returned from the Mythic server
type Response struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Error message returned from Mythic HTTP profile
type Error struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

type Tasking struct {
	Action string `json:"action"`
	Size   int    `json:"tasking_size"`
}

type Tasks struct {
	Action string `json:"action"`
	Tasks  []Task `json:"tasks"`
}

type Task struct {
	ID      string  `json:"id"`
	Command string  `json:"command"`
	Params  string  `json:"parameters"`
	Time    float64 `json:"timestamp"`
}

type Job struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

type PostResponse struct {
	Action    string               `json:"action"`
	Responses []ClientTaskResponse `json:"responses"`
}

// ClientTaskResponse is the structure used to return the results of a task to the Mythic server
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
type ClientTaskResponse struct {
	ID        uuid.UUID `json:"task_id"`
	Output    string    `json:"user_output"`
	Status    string    `json:"status"`
	Completed bool      `json:"completed"`
}

// ServerTaskResponse is the message Mythic returns to the client after it sent a ClientTaskResponse message
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
type ServerTaskResponse struct {
	ID     string `json:"task_id"`
	Status string `json:"status"`
	Error  string `json:"error`
}

type ServerPostResponse struct {
	Action    string               `json:"action"`
	Responses []ServerTaskResponse `json:"responses"`
}
