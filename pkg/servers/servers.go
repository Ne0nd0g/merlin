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

package servers

import (
	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/handlers"
)

const (
	// Supported protocols

	// HTTP is HTTP/1.1 Clear-Text protocol
	HTTP int = 1
	// HTTPS is HTTP/1.1 Secure (over SSL/TLS) protocol
	HTTPS int = 2
	// H2C is HTTP/2.0 Clear-Text protocol
	H2C int = 3
	// HTTP2 is HTTP/2.0 Secure (over SSL/TLS)
	HTTP2 int = 4
	// HTTP3 is HTTP/2.0 Secure over Quick UDP Internet Connection (QUIC)
	HTTP3 int = 5
	// DNS is Domain Name Service protocol
	DNS int = 6

	// Server states

	// Stopped is the server's state when it has not ever been started
	Stopped int = 0
	// Running means the server is actively accepting connections and serving content
	Running int = 1
	// Error is used when there was an error operating the server
	Error int = 2
	// Closed is used when the server was running but has been stopped; it can't be reused again
	Closed int = 3
)

// RegisteredServers contains an array of registered listener types
var RegisteredServers = make(map[string]string) // TODO not sure what to do with the value just yet, might change type

// ServerInterface is used to provide a standard set of methods a server module must support to work with Merlin
type ServerInterface interface {
	GetConfiguredOptions() map[string]string
	GetContext() handlers.ContextInterface
	GetInterface() string
	GetProtocol() int
	GetProtocolString() string
	GetPort() int
	SetOption(string, string) error
	Start() error
	Status() int
	Stop() error
}

// Server structure is used to provide a standard set of fields a server module must support to work with Merlin
type Server struct {
	ServerInterface
	ID        uuid.UUID   // Unique identifier for the Server object
	Transport interface{} // The server, or transport, that will be used to send and receive traffic
	Interface string      // The network adapter interface the server will listen on
	Port      int         // The port the server will listen on
	Protocol  int         // The protocol (i.e. HTTP/2 or HTTP/3) the server will use from the servers package
	State     int
}

// Template is a structure used to collect the information needed to create an new server instance
type Template struct {
	Interface string
	Port      string
	Protocol  string
}

// GetProtocol is used to transform a server protocol constant into a string for use in written messages or logs
func GetProtocol(protocol int) string {
	switch protocol {
	case HTTP:
		return "HTTP"
	case HTTPS:
		return "HTTPS"
	case H2C:
		return "H2C"
	case HTTP2:
		return "HTTP2"
	case HTTP3:
		return "HTTP3"
	case DNS:
		return "DNS"
	default:
		return "invalid protocol"
	}
}

// GetStateString is used to transform a server state constant into a string for use in written messages or logs
func GetStateString(state int) string {
	switch state {
	case Stopped:
		return "Stopped"
	case Running:
		return "Running"
	case Error:
		return "Error"
	case Closed:
		return "Closed"
	default:
		return "Undefined"
	}
}
