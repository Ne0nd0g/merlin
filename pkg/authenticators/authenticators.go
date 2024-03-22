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

// Package authenticators holds the factories to create structures that implement the Authenticator interface
// This interface is used to authenticate agents
package authenticators

import (
	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"
)

// Authenticator is an interface used by various authentication methods
type Authenticator interface {
	// Authenticate is the server-side steps to complete Agent authentication
	Authenticate(id uuid.UUID, data interface{}) (messages.Base, error) // Returning Base so that way it can be sent to the agent
	// String returns the name of authenticator type
	String() string
}
