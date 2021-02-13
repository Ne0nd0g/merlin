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

package messages

import (
	// Standard
	"fmt"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"
)

const (
	// Info messages are used just to inform the user and do not indicate that an action is required
	Info int = 0
	// Note messages are used similar to verbose messages and are used to keep the user up to date
	Note int = 1
	// Warn messages are used to notify the user that there was an error or that something didn't work as planned
	Warn int = 2
	// Debug messages are displayed while debugging the program and display a lot of information
	Debug int = 3
	// Success messages are you to notify the user that an action was completed without error
	Success int = 4
	// Plain messages have no color or other formatting applied and are used for edge cases
	Plain int = 5
)

// messageChannel is a map of all registered clients where messages can be queued in a channel for the client
var messageChannel = make(map[uuid.UUID]chan UserMessage)

// UserMessage is a structure that holds messages that will be presented to the user
type UserMessage struct {
	Level   int       // Message level (i.e. Info, Debug, Verbose)
	Message string    // The text to be displayed
	Time    time.Time // Time the message was generated
	Error   bool      // Is the message the result of an error?
}

// Register lets the sever know that a client exists and that it can be sent messages
func Register(clientID uuid.UUID) UserMessage {
	if _, ok := messageChannel[clientID]; !ok {
		messageChannel[clientID] = make(chan UserMessage)
		return UserMessage{
			Level:   Success,
			Message: "successfully registered client for user message channel with server",
			Time:    time.Now().UTC(),
			Error:   false,
		}
	}
	return UserMessage{
		Level:   Warn,
		Message: fmt.Sprintf("client %s already registered for user a user message channel with server", clientID),
		Time:    time.Now().UTC(),
		Error:   true,
	}
}

// SendBroadcastMessage adds the input message to the channel for all registered clients
func SendBroadcastMessage(message UserMessage) {
	for c := range messageChannel {
		messageChannel[c] <- message
	}
}

// GetMessageForClient is used by a client to receive any queued messages for it
func GetMessageForClient(clientID uuid.UUID) UserMessage {
	if _, ok := messageChannel[clientID]; ok {
		return <-messageChannel[clientID]
	}
	return UserMessage{
		Level:   Warn,
		Message: fmt.Sprintf(" could not get messages for client %s because it does not exist", clientID),
		Time:    time.Now().UTC(),
		Error:   true,
	}
}

// ErrorMessage returns a pre-formatted error message for an input string
func ErrorMessage(message string) UserMessage {
	return UserMessage{
		Error:   true,
		Level:   Warn,
		Time:    time.Now().UTC(),
		Message: message,
	}
}

// JobMessage returns a message showing that an agent job was successfully created
func JobMessage(agentID uuid.UUID, jobID string) UserMessage {
	m := fmt.Sprintf("Created job %s for agent %s at %s", jobID, agentID, time.Now().UTC().Format(time.RFC3339))
	return UserMessage{
		Error:   false,
		Level:   Note,
		Message: m,
		Time:    time.Now().UTC(),
	}
}

// DelayedMessage is used to return messages to a client that are delayed or deferred for items like go routines
func DelayedMessage(message UserMessage) {
	SendBroadcastMessage(message)
}
