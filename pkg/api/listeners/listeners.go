// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2020  Russel Van Tuyl

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
	"strings"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/listeners"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// Exists determines if the input listener name is an instantiated object
func Exists(name string) messages.UserMessage {
	_, err := listeners.GetListenerByName(name)
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
	l, err := listeners.New(options)
	if err != nil {
		return messages.ErrorMessage(err.Error()), uuid.Nil
	}
	m := fmt.Sprintf("%s listener was created with an ID of: %s", l.Name, l.ID)
	um := messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: m,
		Error:   false,
	}
	return um, l.ID
}

// Remove deletes and removes the listener from the server
func Remove(name string) messages.UserMessage {
	l, errL := listeners.GetListenerByName(name)
	if errL != nil {
		return messages.ErrorMessage(errL.Error())
	}
	err := listeners.RemoveByID(l.ID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	m := fmt.Sprintf("deleted listener %s:%s", l.Name, l.ID)
	return messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: m,
		Error:   false,
	}
}

// Restart restarts the Listener's server
func Restart(listenerID uuid.UUID) messages.UserMessage {
	l, err := listeners.GetListenerByID(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	errRestart := l.Restart(l.GetConfiguredOptions())
	if errRestart != nil {
		return messages.ErrorMessage(errRestart.Error())
	}

	// TODO not sure if this should be here or in the listeners package
	go func() {
		err := l.Server.Start()
		if err != nil {
			messages.DelayedMessage(messages.ErrorMessage(err.Error()))
		}
	}()
	return messages.UserMessage{
		Level:   messages.Success,
		Time:    time.Now().UTC(),
		Message: fmt.Sprintf("%s listener was successfully restarted", l.Name),
		Error:   false,
	}
}

// SetOption sets the value of a configurable Listener option
func SetOption(listenerID uuid.UUID, Args []string) messages.UserMessage {
	l, err := listeners.GetListenerByID(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	if len(Args) >= 2 {
		for k := range l.GetConfiguredOptions() {
			if Args[1] == k {
				v := strings.Join(Args[2:], " ")
				err := l.SetOption(k, v)
				if err != nil {
					return messages.ErrorMessage(err.Error())
				}
				return messages.UserMessage{
					Error:   false,
					Level:   messages.Success,
					Time:    time.Now().UTC(),
					Message: fmt.Sprintf("set %s to: %s", k, v),
				}
			}
		}
	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Listeners SetOption call: %s", Args))
}

// Start runs the Listener's server
func Start(name string) messages.UserMessage {
	l, err := listeners.GetListenerByName(name)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	switch l.Server.Status() {
	case servers.Running:
		return messages.UserMessage{
			Error:   false,
			Level:   messages.Note,
			Time:    time.Now().UTC(),
			Message: "the server is already running",
		}
	case servers.Stopped:
		go func() {
			err := l.Server.Start()
			if err != nil {
				messages.DelayedMessage(messages.ErrorMessage(err.Error()))
			}
		}()
		return messages.UserMessage{
			Error: false,
			Level: messages.Success,
			Time:  time.Now().UTC(),
			Message: fmt.Sprintf("Started %s listener on %s:%d", servers.GetProtocol(l.Server.GetProtocol()),
				l.Server.GetInterface(),
				l.Server.GetPort()),
		}
	case servers.Closed:
		if err := l.Restart(l.GetConfiguredOptions()); err != nil {
			return messages.ErrorMessage(err.Error())
		}
		go func() {
			err := l.Server.Start()
			if err != nil {
				messages.DelayedMessage(messages.ErrorMessage(err.Error()))
			}
		}()
		return messages.UserMessage{
			Error: false,
			Level: messages.Success,
			Time:  time.Now().UTC(),
			Message: fmt.Sprintf("Restarted %s %s listener on %s:%d", l.Name, servers.GetProtocol(l.Server.GetProtocol()),
				l.Server.GetInterface(),
				l.Server.GetPort()),
		}
	default:
		return messages.UserMessage{
			Error:   true,
			Level:   messages.Warn,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("unhandled server status: %s", servers.GetStateString(l.Server.Status())),
		}
	}
}

// Stop terminates the Listener's server
func Stop(name string) messages.UserMessage {
	l, err := listeners.GetListenerByName(name)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	if l.Server.Status() == servers.Running {
		err := l.Server.Stop()
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.UserMessage{
			Error:   false,
			Level:   messages.Success,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("%s listener was stopped", l.Name),
		}
	}
	return messages.UserMessage{
		Error:   false,
		Level:   messages.Note,
		Time:    time.Now().UTC(),
		Message: "this listener is not running",
	}
}

// GetListenerStatus returns the Listener's server status
func GetListenerStatus(listenerID uuid.UUID) messages.UserMessage {
	l, err := listeners.GetListenerByID(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.UserMessage{
		Level:   messages.Plain,
		Message: servers.GetStateString(l.Server.Status()),
		Time:    time.Time{},
		Error:   false,
	}
}

// GetListenerByName return the unique identifier for an instantiated Listener by its name
func GetListenerByName(name string) (messages.UserMessage, uuid.UUID) {
	l, err := listeners.GetListenerByName(name)
	if err != nil {
		return messages.ErrorMessage(err.Error()), uuid.Nil
	}
	um := messages.UserMessage{
		Error: false,
		Time:  time.Now().UTC(),
	}
	return um, l.ID
}

// GetListenerConfiguredOptions enumerates all of a Listener's settings and returns them
func GetListenerConfiguredOptions(listenerID uuid.UUID) (messages.UserMessage, map[string]string) {
	l, err := listeners.GetListenerByID(listenerID)
	if err != nil {
		return messages.ErrorMessage(err.Error()), nil
	}
	um := messages.UserMessage{
		Message: "",
		Time:    time.Now().UTC(),
		Error:   false,
	}
	return um, l.GetConfiguredOptions()
}

// GetListeners returns a list of an instantiated Listeners
func GetListeners() []listeners.Listener {
	return listeners.GetListeners()
}

// GetListenerTypes returns the supported server protocols that are available to be used with a Listener
func GetListenerTypes() []string {
	return listeners.GetListenerTypes()
}

// GetListenerOptions returns all of the configurable options for an uninstatiated listener based on the provided protocol type
func GetListenerOptions(protocol string) map[string]string {
	return listeners.GetListenerOptions(protocol)
}

// TODO Move the completers to the CLI package

// GetListenerNamesCompleter returns CLI tab completer for available Listeners
func GetListenerNamesCompleter() func(string) []string {
	return listeners.GetList()
}

// GetListenerOptionsCompleter returns CLI tab completer for supported Listener server protocols
func GetListenerOptionsCompleter(protocol string) func(string) []string {
	return listeners.GetListenerOptionsCompleter(protocol)
}

// GetListenerTypesCompleter returns CLI tab completer for available Listener types
func GetListenerTypesCompleter() func(string) []string {
	return listeners.GetListenerTypesCompleter()
}
