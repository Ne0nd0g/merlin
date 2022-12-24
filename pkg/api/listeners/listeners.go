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

package listeners

import (
	// Standard
	"fmt"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/services/listeners"
)

var listenerService listeners.ListenerService

func init() {
	listenerService = listeners.NewListenerService()
}

// Exists determines if the input listener name is an instantiated object
func Exists(name string) messages.UserMessage {
	_, err := listenerService.ListenerByName(name)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.UserMessage{
		Time:  time.Now().UTC(),
		Error: false,
	}
}

// NewListener instantiates a new Listener object on the server
func NewListener(options map[string]string) (messages.UserMessage, uuid.UUID) {
	listener, err := listenerService.NewListener(options)
	if err != nil {
		return messages.ErrorMessage(err.Error()), uuid.Nil
	}
	m := fmt.Sprintf("%s listener was created with an ID of: %s", listener, listener.ID())
	um := messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: m,
		Error:   false,
	}

	return um, listener.ID()
}

// Remove deletes and removes the listener from the server
func Remove(name string) messages.UserMessage {
	l, err := listenerService.ListenerByName(name)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	err = listenerService.Remove(l.ID())
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	m := fmt.Sprintf("deleted listener %s:%s", l, l.ID())
	return messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: m,
		Error:   false,
	}
}

// Restart restarts the Listener's server
func Restart(listenerID uuid.UUID) messages.UserMessage {
	err := listenerService.Restart(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}

	return messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: fmt.Sprintf("%s listener was successfully restarted", listenerID),
		Error:   false,
	}
}

// SetOption sets the value of a configurable Listener option
func SetOption(listenerID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) >= 2 {
		option := make(map[string]string)
		option[Args[0]] = Args[1]
		err := listenerService.SetOptions(listenerID, option)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.UserMessage{
			Error:   false,
			Level:   messages.Success,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("set %s to: %s", Args[0], Args[1]),
		}
	}

	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Listeners SetOption call: %s", Args))
}

// Start runs the Listener's server
func Start(listenerID uuid.UUID) messages.UserMessage {
	err := listenerService.Start(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	l, err := listenerService.Listener(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	if l.Server() != nil {
		server := *l.Server()
		return messages.UserMessage{
			Level:   messages.Note,
			Message: fmt.Sprintf("Started %s server on %s:%d", server.ProtocolString(), server.Interface(), server.Port()),
			Time:    time.Now().UTC(),
			Error:   false,
		}
	}
	// Not all listeners have an infrastructure layer server
	return messages.UserMessage{
		Level:   messages.Note,
		Message: fmt.Sprintf("Started %s listener", l.Name()),
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// Stop terminates the Listener's server
func Stop(listenerID uuid.UUID) messages.UserMessage {
	err := listenerService.Stop(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.UserMessage{
		Error:   false,
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: fmt.Sprintf("%s listener was stopped", listenerID),
	}
}

// GetListenerStatus returns the Listener's server status
func GetListenerStatus(listenerID uuid.UUID) messages.UserMessage {
	l, err := listenerService.Listener(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}

	return messages.UserMessage{
		Level:   messages.Plain,
		Message: l.Status(),
		Time:    time.Time{},
		Error:   false,
	}
}

// GetListenerByName return the unique identifier for an instantiated Listener by its name
func GetListenerByName(name string) (messages.UserMessage, uuid.UUID) {
	l, err := listenerService.ListenerByName(name)
	if err != nil {
		return messages.ErrorMessage(err.Error()), uuid.Nil
	}
	um := messages.UserMessage{
		Error: false,
		Time:  time.Now().UTC(),
	}
	return um, l.ID()
}

// GetListenerConfiguredOptions enumerates all of a Listener's settings and returns them
func GetListenerConfiguredOptions(listenerID uuid.UUID) (messages.UserMessage, map[string]string) {
	l, err := listenerService.Listener(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error()), nil
	}
	um := messages.UserMessage{
		Message: "",
		Time:    time.Now().UTC(),
		Error:   false,
	}
	return um, l.ConfiguredOptions()
}

func GetDefaultOptionsCompleter(listenerType string) func(string) []string {
	return func(line string) []string {
		listenerOptions, _ := listenerService.DefaultOptions(listenerType)
		options := make([]string, 0)
		for k := range listenerOptions {
			options = append(options, k)
		}
		return options
	}
}
