// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package clients

import (
	// Internal
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// ClientInterface is a structure definition of required functions a client must implement to be used with a Merlin Agent
type ClientInterface interface {
	Initial(info messages.AgentInfo) (messages.Base, error)
	SendMerlinMessage(base messages.Base) (messages.Base, error)
	Set(key string, value string) error
	Get(key string) string
	Auth(authType string, register bool) (messages.Base, error)
}

// MerlinClient is base structure for any clients that can be used to send or receive Merlin messages
type MerlinClient struct {
	ClientInterface
}
