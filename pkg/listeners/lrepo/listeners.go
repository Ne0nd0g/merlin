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

package lrepo

import (
	// Standard
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/listeners"
	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// Listeners contains all of the instantiated Listener objects
var Listeners = make(map[uuid.UUID]*listeners.Listener)

// GetList returns a list of Listeners that exist and is used for command line tab completion
func GetList() func(string) []string {
	return func(line string) []string {
		listeners := make([]string, 0)
		for listenerUUID := range Listeners {
			listeners = append(listeners, Listeners[listenerUUID].Name)
		}
		return listeners
	}
}

// GetListenerByID finds and returns a pointer to an instantiated listener object by its ID (UUIDv4)
func GetListenerByID(id uuid.UUID) (*listeners.Listener, error) {
	l, exists := Listeners[id]
	if !exists {
		return nil, fmt.Errorf(fmt.Sprintf("a listener with an ID of %s does not exist", id))
	}
	return l, nil
}

// GetListenerByName finds and returns a pointer to an instantiated listener object by its name (string)
func GetListenerByName(name string) (*listeners.Listener, error) {
	if !Exists(name) {
		return nil, fmt.Errorf("%s listener does not exist", name)
	}

	var listener *listeners.Listener
	for k, v := range Listeners {
		if name == v.Name {
			listener = Listeners[k]
			break
		}
	}
	return listener, nil
}

// GetListenerTypesCompleter returns a list of listener types that Merlin supports for CLI tab completion
func GetListenerTypesCompleter() func(string) []string {
	return func(line string) []string {
		return GetListenerTypes()
	}
}

// GetListenerTypes returns a list of listener types that Merlin supports
func GetListenerTypes() []string {
	var t []string
	for v := range servers.RegisteredServers {
		t = append(t, v)
	}
	return t
}

// Exists determines if the Listener has already been instantiated
func Exists(name string) bool {
	for _, v := range Listeners {
		if name == v.Name {
			return true
		}
	}
	return false
}

// RemoveByID deletes a Listener from the global list of Listeners by the input UUID
func RemoveByID(id uuid.UUID) error {
	if _, ok := Listeners[id]; ok {
		err := Listeners[id].Server.Stop()
		if err != nil {
			return err
		}
		delete(Listeners, id)
		return nil
	}
	return fmt.Errorf("could not remove listener: %s because it does not exist", id)
}

// GetListeners is used to return a list of Listener objects to be consumed by a client application
func GetListeners() []*listeners.Listener {
	var found []*listeners.Listener
	for id := range Listeners {
		found = append(found, Listeners[id])
	}
	return found
}
