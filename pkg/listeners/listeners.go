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

// Package listeners houses listeners for various protocols to receive, handle, and return Agent traffic
package listeners

import (
	// Standard
	"fmt"
	"strings"

	//3rd Party
	"github.com/google/uuid"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/authenticators"
	"github.com/Ne0nd0g/merlin/v2/pkg/servers"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer"
)

const (
	UNKNOWN = 0
	HTTP    = 1 // HTTP is a constant for all HTTP listener types (e.g., HTTP/1, HTTP/2, and HTTP/3)
	TCP     = 2 // TCP is a constant for TCP bind & reverse listeners
	UDP     = 3 // UDP is a constant for UDP bind & reverse listeners
	SMB     = 4 // SMB is a constant for SMB named pipe bind & reverse listeners
)

// Listener is an interface that contains all the functions any Agent listener must implement
type Listener interface {
	Addr() string
	Authenticator() authenticators.Authenticator
	Authenticate(id uuid.UUID, data interface{}) (messages.Base, error)
	ConfiguredOptions() map[string]string
	Construct(msg messages.Base, key []byte) (data []byte, err error)
	Deconstruct(data, key []byte) (messages.Base, error)
	Description() string
	ID() uuid.UUID
	Name() string
	Options() map[string]string
	Protocol() int
	PSK() string
	Server() *servers.ServerInterface
	Status() string
	Transformers() []transformer.Transformer
}

// FromString converts a string representation of the Listener type, or kind, to a constant
func FromString(kind string) int {
	switch strings.ToLower(kind) {
	case "http", "https", "h2c", "http2", "http3":
		return HTTP
	case "smb":
		return SMB
	case "tcp":
		return TCP
	case "udp":
		return UDP
	default:
		return UNKNOWN
	}
}

func String(kind int) string {
	switch kind {
	case HTTP:
		return "HTTP"
	case SMB:
		return "SMB"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown Listener type: %d", kind)
	}
}

func Listeners() []int {
	return []int{HTTP, SMB, TCP, UDP}
}
