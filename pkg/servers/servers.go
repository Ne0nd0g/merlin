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

// Package servers contains servers for various protocols to listen for and return Agent communications
package servers

import (
	// Standard
	"strings"

	// 3rd Party
	"github.com/google/uuid"
)

// Supported protocols
const (
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
)

// RegisteredServers contains an array of registered server types
var RegisteredServers = make(map[int]string)

// ServerInterface is used to provide a standard set of methods a server module must support to work with Merlin
type ServerInterface interface {
	Addr() string
	ConfiguredOptions() map[string]string
	ID() uuid.UUID
	Interface() string
	Listen() error
	Protocol() int
	ProtocolString() string
	Port() int
	SetOption(string, string) error
	Start()
	Status() string
	Stop() error
}

// Protocol is used to transform a server protocol constant into a string for use in written messages or logs
func Protocol(protocol int) string {
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
	default:
		return "invalid protocol"
	}
}

// FromString converts a protocol constant to its string representation
func FromString(protocol string) int {
	switch strings.ToLower(protocol) {
	case "http":
		return HTTP
	case "https":
		return HTTPS
	case "h2c":
		return H2C
	case "http2":
		return HTTP2
	case "http3":
		return HTTP3
	default:
		return 0
	}
}
