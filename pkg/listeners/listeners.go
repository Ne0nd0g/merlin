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
	"strings"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/servers"
	"github.com/Ne0nd0g/merlin/pkg/servers/http"
	"github.com/Ne0nd0g/merlin/pkg/servers/http2"
	"github.com/Ne0nd0g/merlin/pkg/servers/http3"
)

// Listeners contains all of the instantiated Listener objects
var Listeners = make(map[uuid.UUID]*Listener)

// Listener is a structure for created Merlin listener with an embedded Server object
type Listener struct {
	ID          uuid.UUID               // Unique identifier for the Listener object
	Name        string                  // Name of the listener
	Description string                  // A description of the listener
	Server      servers.ServerInterface // Interface to interact with server objects
}

// New instantiates a Listener object
func New(options map[string]string) (*Listener, error) {
	var listener Listener
	var err error

	// Ensure a listener name was provided
	listener.Name = options["Name"]
	if listener.Name == "" {
		return &listener, fmt.Errorf("a listener name must be provided")
	}
	// Ensure a listener with this name does not exist
	if Exists(listener.Name) {
		return &listener, fmt.Errorf("a listener with this name already exists")
	}

	// Get a new server object for the listener
	switch strings.ToLower(options["Protocol"]) {
	case "":
		return &listener, fmt.Errorf("a listener protocol must be provided")
	case "http", "https", "http2":
		listener.Server, err = http.New(options)
	case "h2c":
		listener.Server, err = http2.New(options)
	case "http3":
		listener.Server, err = http3.New(options)

	default:
		err = fmt.Errorf("invalid listener server type: %s", options["Protocol"])
	}

	if err != nil {
		return &listener, err
	}

	listener.ID = uuid.NewV4()
	listener.Description = options["Description"]

	Listeners[listener.ID] = &listener

	return &listener, nil
}

// GetConfiguredOptions returns the server's current configuration for options that can be set by the user
func (l *Listener) GetConfiguredOptions() map[string]string {
	options := l.Server.GetConfiguredOptions()
	options["Name"] = l.Name
	options["Description"] = l.Description
	options["ID"] = l.ID.String()
	return options
}

// Restart creates a new server instance because http servers can not be reused after they are stopped
func (l *Listener) Restart(options map[string]string) error {
	var err error

	// Stop the running instance
	if l.Server.Status() == servers.Running {
		if err = l.Server.Stop(); err != nil {
			return err
		}
	}

	// Create a new instance
	switch l.Server.GetProtocol() {
	case servers.HTTP, servers.HTTPS, servers.HTTP2:
		l.Server, err = http.Renew(l.Server.GetContext(), options)
	case servers.H2C:
		l.Server, err = http2.Renew(l.Server.GetContext(), options)
	case servers.HTTP3:
		l.Server, err = http3.Renew(l.Server.GetContext(), options)
	default:
		err = fmt.Errorf("invalid server protocol: %d (%s)", l.Server.GetProtocol(), servers.GetProtocol(l.Server.GetProtocol()))
	}
	return err
}

// SetOption sets the value for a configurable option on the Listener
func (l *Listener) SetOption(option string, value string) error {
	switch strings.ToLower(option) {
	case "name":
		l.Name = value
	case "description":
		l.Description = value
	default:
		return l.Server.SetOption(option, value)
	}
	return nil
}

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
func GetListenerByID(id uuid.UUID) (*Listener, error) {
	l, exists := Listeners[id]
	if !exists {
		return &Listener{}, fmt.Errorf(fmt.Sprintf("a listener with an ID of %s does not exist", id))
	}
	return l, nil
}

// GetListenerByName finds and returns a pointer to an instantiated listener object by its name (string)
func GetListenerByName(name string) (*Listener, error) {

	if !Exists(name) {
		return &Listener{}, fmt.Errorf("%s listener does not exist", name)
	}
	var listener *Listener
	for k, v := range Listeners {
		if name == v.Name {
			listener = Listeners[k]
			break
		}
	}
	return listener, nil
}

// GetListenerOptions gets a map of all configurable module options
func GetListenerOptions(protocol string) map[string]string {
	var options map[string]string
	switch strings.ToLower(protocol) {
	case "http", "https", "http2":
		options = http.GetOptions(strings.ToLower(protocol))
	case "h2c":
		options = http2.GetOptions()
	case "http3":
		options = http3.GetOptions()
	default:
		options = make(map[string]string)
	}
	options["Name"] = "Default"
	options["Description"] = "Default listener"
	return options
}

// GetListenerOptionsCompleter gets an array of listener options to be used for tab completion for CLI tab completion
func GetListenerOptionsCompleter(protocol string) func(string) []string {
	return func(line string) []string {
		var serverOptions map[string]string
		options := make([]string, 0)
		switch strings.ToLower(protocol) {
		case "http", "https", "http2":
			serverOptions = http.GetOptions(strings.ToLower(protocol))
		case "h2c":
			serverOptions = http2.GetOptions()
		case "http3":
			serverOptions = http3.GetOptions()
		default:
			serverOptions = make(map[string]string)
		}
		for k := range serverOptions {
			options = append(options, k)
		}
		options = append(options, "Name")
		options = append(options, "Description")
		return options
	}
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
func GetListeners() []Listener {
	var listeners []Listener
	for id := range Listeners {
		listeners = append(listeners, *Listeners[id])
	}
	return listeners
}
