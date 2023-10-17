/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

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

package memory

import (
	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
)

type Repository struct {
	messages chan *message.UserMessage
}

// repo is the in-memory database
var repo *Repository

func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			messages: make(chan *message.UserMessage, 100),
		}
	}
	return repo
}

// Add adds a message to the repository's clients channel
func (r *Repository) Add(message *message.UserMessage) {
	r.messages <- message
	return
}

// Get returns a message from the repository's clients channel
func (r *Repository) Get() *message.UserMessage {
	return <-r.messages
}
