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

package message

import (
	"time"
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

// UserMessage is a structure that holds messages that will be presented to the user
type UserMessage struct {
	level     Level     // level of the message (i.e. Info, Debug, Verbose)
	message   string    // message is the text to be displayed
	timestamp time.Time // timestamp the message was generated
	isError   bool      // isError indicates if this message is an error
}

// NewUserMessage is a factory that builds and returns a UserMessage structure
// The Time field is set to the current time as UTC
// Use the NewErrorMessage factory to create an error message
func NewUserMessage(level Level, message string) *UserMessage {
	return &UserMessage{
		level:     level,
		message:   message,
		timestamp: time.Now().UTC(),
		isError:   false,
	}
}

// NewUserMessageFull is a factory that builds and returns a UserMessage structure
// Typically used to convert a pb.Message structure to a UserMessage structure so that the timestamp can be transfered
func NewUserMessageFull(level Level, message string, timestamp time.Time, isError bool) *UserMessage {
	return &UserMessage{
		level:     level,
		message:   message,
		timestamp: timestamp,
		isError:   isError,
	}
}

// NewErrorMessage is a factory that builds and returns a UserMessage structure
func NewErrorMessage(err error) *UserMessage {
	return &UserMessage{
		level:     Warn,
		message:   err.Error(),
		timestamp: time.Now().UTC(),
		isError:   true,
	}
}

// LevelFromInt32 converts an int32 to a Level
func LevelFromInt32(level int32) Level {
	switch level {
	case 1:
		return Info
	case 2:
		return Note
	case 3:
		return Warn
	case 4:
		return Debug
	case 5:
		return Success
	case 6:
		return Plain
	default:
		return Undefined
	}
}

func (um *UserMessage) Level() Level {
	return um.level
}

func (um *UserMessage) Message() string {
	return um.message
}

func (um *UserMessage) Timestamp() time.Time {
	return um.timestamp
}

func (um *UserMessage) Error() bool {
	return um.isError
}
