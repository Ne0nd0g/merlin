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

package tcp

import (
	// Standard
	"fmt"
	"net"
	"strconv"
	"strings"

	//3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/handlers"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// init registers this server type with the servers package
func init() {
	// Register Server
	servers.RegisteredServers["tcp"] = ""
}

// Template is a structure used to collect the information needed to create an instance with the New() function
type Template struct {
	servers.Template
	PSK string // The pre-shared key password used prior to Password Authenticated Key Exchange (PAKE)
}

// New creates a new HTTP server object and returns a pointer
// All arguments are taken in as strings and are converted/validate
func New(options map[string]string) (server *Server, err error) {
	// Verify protocol match
	if strings.ToLower(options["Protocol"]) != "tcp" {
		err = fmt.Errorf("server protocol mismatch, expected: HTTP3 got: %s", options["Protocol"])
		return
	}

	server = &Server{}
	server.Protocol = servers.TCP

	// Parse interface
	if options["Interface"] == "" {
		err = fmt.Errorf("a network interface address must be provided")
		return
	}
	ip := net.ParseIP(options["Interface"])
	if ip == nil {
		err = fmt.Errorf("%s is not a valid network interface", options["Interface"])
		return
	}
	server.Interface = options["Interface"]

	// Convert port to integer from string
	if options["Port"] == "" {
		err = fmt.Errorf("a network interface port must be provided")
		return
	}
	server.Port, err = strconv.Atoi(options["Port"])
	if err != nil {
		err = fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
		return
	}

	// Pre-Shared Key
	if options["PSK"] == "" {
		err = fmt.Errorf("a Pre-Shared Key (PSK) password must be provided")
		return
	}
	server.psk = options["PSK"]

	// Everything else
	server.ID = uuid.NewV4()
	server.State = servers.Stopped

	return
}

// GetOptions returns a map of configurable server options typically used when creating a listener
func GetOptions() map[string]string {
	options := make(map[string]string)
	options["Interface"] = "127.0.0.1"
	options["Port"] = "443"
	options["PSK"] = "merlin"
	return options
}

// Server is a structure for the HTTP3 server
type Server struct {
	servers.Server
	psk string
}

// GetConfiguredOptions returns the server's current configuration for options that can be set by the user
func (s *Server) GetConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Interface"] = s.Interface
	options["Port"] = fmt.Sprintf("%d", s.Port)
	options["Protocol"] = servers.GetProtocol(s.Protocol)
	options["PSK"] = s.psk

	return options
}

// GetContext returns the Server's current context information such as encryption keys
func (s *Server) GetContext() handlers.ContextInterface {
	return nil
}

// GetInterface function returns the interface that the server is bound to
func (s *Server) GetInterface() string {
	return s.Interface
}

// GetPort function returns the port that the server is bound to
func (s *Server) GetPort() int {
	return s.Port
}

// GetProtocol returns the server's protocol as an integer for a constant in the servers package
func (s *Server) GetProtocol() int {
	return s.Protocol
}

// GetProtocolString function returns the server's protocol
func (s *Server) GetProtocolString() string {
	switch s.Protocol {
	case servers.TCP:
		return "TCP"
	default:
		return "UNKNOWN"
	}
}

// SetOption function sets an option for an instantiated server object
func (s *Server) SetOption(option string, value string) error {
	var err error
	// Check non-string options first
	switch strings.ToLower(option) {
	case "interface":
		s.Interface = value
	case "port":
		s.Port, err = strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
		}
	case "protocol":
		return fmt.Errorf("the protocol can not be changed; create a new listener instead")
	case "psk":
		s.psk = value
	default:
		return fmt.Errorf("invalid option: %s", option)
	}
	return nil
}

// Start function starts the HTTP3 server
func (s *Server) Start() (err error) {
	// This listener is for a TCP bind lister that will run on an agent, not the server
	// Therefore there is nothing to start here at the server
	s.State = servers.Running
	return
}

// Stop function stops the HTTP3 server
func (s *Server) Stop() (err error) {
	// This listener is for a TCP bind lister that will run on an agent, not the server
	// Therefore there is nothing to stop here at the server
	s.State = servers.Stopped
	return
}

// Status enumerates if the server is currently running or stopped and returns the value as a string
func (s *Server) Status() int {
	return s.State
}
