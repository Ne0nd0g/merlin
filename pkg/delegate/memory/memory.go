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

package memory

import (
	"github.com/google/uuid"
	"sync"
)

type delegate struct {
	data []byte
}

type Repository struct {
	messages map[uuid.UUID][]delegate
	sync.Mutex
}

// repo is the in-memory datastore
var repo *Repository

// NewRepository is a factory to return a repository structure
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{messages: make(map[uuid.UUID][]delegate)}
	}
	return repo
}

// Add data to the in-memory map for the provided Agent ID
func (r *Repository) Add(id uuid.UUID, data []byte) {
	var exists bool
	for k := range r.messages {
		if id == k {
			exists = true
		}
	}
	r.Lock()
	defer r.Unlock()
	if exists {
		r.messages[id] = append(r.messages[id], delegate{data: data})
	} else {
		r.messages[id] = []delegate{{data: data}}
	}
}

// Get return data from the in-memory map for the provided Agent ID
func (r *Repository) Get(id uuid.UUID) [][]byte {
	r.Lock()
	defer r.Unlock()
	var returnMessages [][]byte
	for k, msgs := range r.messages {
		if k == id {
			for _, v := range msgs {
				returnMessages = append(returnMessages, v.data)
			}
			delete(r.messages, k)
		}
	}
	return returnMessages
}
