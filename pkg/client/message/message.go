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

// Package message is used to handle messages created by the Merlin server that need to sent to CLI clients
package message

import (
	// Standard
	"time"

	// 3rd Party
	"github.com/google/uuid"
)

type Level int32

const (
	Undefined Level = iota
	// Info messages are used just to inform the user and do not indicate that an action is required
	Info
	// Note messages are used similar to verbose messages and are used to keep the user up to date
	Note
	// Warn messages are used to notify the user that there was an error or that something didn't work as planned
	Warn
	// Debug messages are displayed while debugging the program and display a lot of information
	Debug
	// Success messages are you to notify the user that an action was completed without error
	Success
	// Plain messages have no color or other formatting applied and are used for edge cases
	Plain
)

// Message is structure used to send user messages to CLI clients
type Message struct {
	id        uuid.UUID
	level     Level
	message   string
	timestamp time.Time
	isError   bool
}

// NewMessage is a factory that builds and returns a Message structure
func NewMessage(level Level, message string) *Message {
	return &Message{
		id:        uuid.New(),
		level:     level,
		message:   message,
		timestamp: time.Now().UTC(),
		isError:   false,
	}
}

func NewErrorMessage(err error) *Message {
	return &Message{
		id:        uuid.New(),
		level:     Warn,
		message:   err.Error(),
		timestamp: time.Now().UTC(),
		isError:   true,
	}
}

// ID returns the unique identifier for the message
func (m Message) ID() uuid.UUID {
	return m.id
}

func (m Message) Error() bool {
	return m.isError
}

// Level returns the level of the message (e.g., Info, Warn, Debug, etc.)
func (m Message) Level() Level {
	return m.level
}

// Message returns the text of the message
func (m Message) Message() string {
	return m.message
}

// String returns the text of the message
func (m Message) String() string {
	return m.message
}

func (m Message) Time() time.Time {
	return m.timestamp
}
