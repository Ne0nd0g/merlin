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

import (
	uuid "github.com/satori/go.uuid"
)

const (
	// CHECKIN is Mythic action https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin
	CHECKIN = "checkin"
	// TASKING is a Mythic action https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action_get_tasking
	TASKING = "get_tasking"
	// RESPONSE is used to send a message back to the Mythic server https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-post_response
	RESPONSE = "post_response"
	// StatusError is used to when there is an error
	StatusError = "error"
	// RSAStaging is used to setup and complete the RSA key exchange https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin
	RSAStaging = "staging_rsa"
	// UPLOAD is a Mythic action https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-upload
	UPLOAD = "upload"

	// Custom

	// DownloadInit is used as the first download message from the Mythic server
	DownloadInit = 300
	// DownloadSend is used after the init message to send the file
	DownloadSend = 301
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

// Tasking is used by the agent to request a specified number of tasks from the server
type Tasking struct {
	Action string `json:"action"`
	Size   int    `json:"tasking_size"`
}

// Tasks holds a list of tasks for the agent to process
type Tasks struct {
	Action string `json:"action"`
	Tasks  []Task `json:"tasks"`
}

// Task contains the task identifier, command, and parameters for the agent to execute
type Task struct {
	ID      string  `json:"id"`
	Command string  `json:"command"`
	Params  string  `json:"parameters"`
	Time    float64 `json:"timestamp"`
}

// Job structure
type Job struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// PostResponse is the structure used to sent a list of messages from the agent to the server
type PostResponse struct {
	Action    string               `json:"action"`
	Responses []ClientTaskResponse `json:"responses"` // TODO This needs to be an interface so it can handle both ClientTaskResponse and FileDownloadInitialMessage
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
	Error  string `json:"error"`
	FileID string `json:"file_id"`
}

// ServerPostResponse structure holds a list of ServerTaskResponse structure
type ServerPostResponse struct {
	Action    string               `json:"action"`
	Responses []ServerTaskResponse `json:"responses"`
}

// RSARequest is used by the client to send the server it's RSA public key
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin#eke-by-generating-client-side-rsa-keys
type RSARequest struct {
	Action    string `json:"action"`     // staging_rsa
	PubKey    string `json:"pub_key"`    // base64 of public RSA key
	SessionID string `json:"session_id"` // 20 character string; unique session ID for this callback
}

// RSAResponse contains the derived session key that is encrypted with the agent's RSA key
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/initial-checkin#eke-by-generating-client-side-rsa-keys
type RSAResponse struct {
	Action     string `json:"action"`      // staging_rsa
	ID         string `json:"uuid"`        // new UUID for the next message
	SessionKey string `json:"session_key"` // Base64( RSAPub( new aes session key ) )
	SessionID  string `json:"session_id"`  // same 20 char string back
}

// PostResponseFile is the structure used to sent a list of messages from the agent to the server
type PostResponseFile struct {
	Action    string                       `json:"action"`
	Responses []FileDownloadInitialMessage `json:"responses"`
}

// FileDownloadInitialMessage contains the information for the initial step of the file download process
type FileDownloadInitialMessage struct {
	NumChunks    int    `json:"total_chunks"`
	TaskID       string `json:"task_id"`
	FullPath     string `json:"full_path"`
	IsScreenshot bool   `json:"is_screenshot"`
}

// PostResponseDownload is used to send a response to the Mythic server
type PostResponseDownload struct {
	Action    string         `json:"action"`
	Responses []FileDownload `json:"responses"`
}

// FileDownload sends a chunk of Base64 encoded data from the agent to the server
type FileDownload struct {
	Chunk  int    `json:"chunk_num"`
	FileID string `json:"file_id"` // UUID from FileDownloadResponse
	TaskID string `json:"task_id"`
	Data   string `json:"chunk_data"` // Base64 encoded data
}

// DownloadResponse is the servers response to a FileDownload message
type DownloadResponse struct {
	Status string `json:"status"`
	TaskID string `json:"task_id"`
}

// UploadRequest is message
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-upload
type UploadRequest struct {
	Action string `json:"action"`
	TaskID string `json:"task_id"`    // the associated task that caused the agent to pull down this file
	FileID string `json:"file_id"`    // the file specified to pull down to the target
	Path   string `json:"full_path"`  // ull path to uploaded file on Agent's host
	Size   int    `json:"chunk_size"` // bytes of file per chunk
	Chunk  int    `json:"chunk_num"`  // which chunk are we currently pulling down
}

// UploadResponse is the message sent from the server to an agent
// https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-upload
type UploadResponse struct {
	Path   string `json:"remote_path"`
	FileID string `json:"file_id"`
}
