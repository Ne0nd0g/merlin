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
	"errors"
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/listener"
	uuid "github.com/satori/go.uuid"
	"sync"
)

type Repository struct {
	listeners []listener.Listener
	sync.Mutex
}

var pkg = "pkg/cli/listener/memory.go"
var ErrListenerNotFound = errors.New(fmt.Sprintf("%s: listener not found", pkg))

// repo is the in-memory database
var repo *Repository

func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{}
	}
	return repo
}

func (r *Repository) Add(listener listener.Listener) {
	r.Lock()
	defer r.Unlock()
	r.listeners = append(r.listeners, listener)
}

func (r *Repository) Get(id uuid.UUID) (listener *listener.Listener, err error) {
	r.Lock()
	defer r.Unlock()
	for _, l := range r.listeners {
		if l.ID() == id {
			return &l, nil
		}
	}
	return nil, ErrListenerNotFound
}

func (r *Repository) Remove(id uuid.UUID) {
	r.Lock()
	defer r.Unlock()
	for i, l := range r.listeners {
		if l.ID() == id {
			r.listeners = append(r.listeners[:i], r.listeners[i+1:]...)
		}
	}
}

func (r *Repository) ServerID(id uuid.UUID, serverID uuid.UUID) (err error) {
	r.Lock()
	defer r.Unlock()
	for i, l := range r.listeners {
		if l.ID() == id {
			l.ServerID(serverID)
			r.listeners[i] = l
			return
		}
	}
	return ErrListenerNotFound
}

func (r *Repository) Update(id uuid.UUID, options map[string]string) error {
	r.Lock()
	defer r.Unlock()
	for i, l := range r.listeners {
		if l.ID() == id {
			l.Update(options)
			r.listeners[i] = l
			return nil
		}
	}
	return ErrListenerNotFound
}
