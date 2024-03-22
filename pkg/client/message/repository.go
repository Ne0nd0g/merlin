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

package message

import "github.com/google/uuid"

type Repository interface {
	// Add store a message in the repository
	Add(message *Message)
	// Get return a specific message by its id
	Get(id uuid.UUID) (msg *Message, err error)
	// GetAll returns all messages in the repository
	GetAll() (messages []*Message)
	// GetQueue returns a message channel queue to receive messages from
	GetQueue() (msg *Message)
}
