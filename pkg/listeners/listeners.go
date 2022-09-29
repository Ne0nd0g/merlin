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
)

type BaseHandler interface {
	In()
	Out()
}

type Encoder interface {
	Encode()
	Decode()
}

type Encrypter interface {
	Encrypt()
	Decrpyt()
}

// Listener is a structure for created Merlin listener with an embedded Server object
type Listener struct {
	ID          uuid.UUID               // Unique identifier for the Listener object
	Name        string                  // Name of the listener
	Description string                  // A description of the listener
	Server      servers.ServerInterface // Interface to interact with server objects
}

// New instantiates a Listener object
func New(server servers.ServerInterface, options map[string]string) (*Listener, error) {
	var listener Listener

	// Ensure a listener name was provided
	listener.Name = options["Name"]
	if listener.Name == "" {
		return &listener, fmt.Errorf("a listener name must be provided")
	}

	// Get a new server object for the listener
	listener.ID = uuid.NewV4()
	listener.Server = server
	listener.Description = options["Description"]

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
	//var err error
	//
	//// Stop the running instance
	//if l.Server.Status() == servers.Running {
	//	if err = l.Server.Stop(); err != nil {
	//		return err
	//	}
	//}
	//
	//// Create a new instance
	//switch l.Server.GetProtocol() {
	//case servers.HTTP, servers.HTTPS, servers.HTTP2:
	//	l.Server, err = http.Renew(l.Server.GetContext(), options)
	//case servers.H2C:
	//	l.Server, err = http2.Renew(l.Server.GetContext(), options)
	//case servers.HTTP3:
	//	l.Server, err = http3.Renew(l.Server.GetContext(), options)
	//default:
	//	err = fmt.Errorf("invalid server protocol: %d (%s)", l.Server.GetProtocol(), servers.GetProtocol(l.Server.GetProtocol()))
	//}
	return l.Server.Restart(options)
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
