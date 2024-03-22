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

// Package memory is an in-memory database used to store and retrieve HTTP servers
package memory

import (
	// Standard
	"fmt"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/servers/http"
)

// Repository is a structure that implements the Repository interface to store & manage Server objects
type Repository struct {
	servers map[uuid.UUID]http.Server
	sync.Mutex
}

// serverMap is the in-memory structure that holds all the created Server objects
var serverMap = make(map[uuid.UUID]http.Server)

// NewRepository is a factory to create and return a repository object to store and manage listeners
func NewRepository() *Repository {
	return &Repository{
		servers: serverMap,
		Mutex:   sync.Mutex{},
	}
}

// Add stores the passed in Server object
func (r *Repository) Add(server http.Server) error {
	// Make sure the map exists and create it if not
	if r.servers == nil {
		r.Lock()
		r.servers = make(map[uuid.UUID]http.Server)
		r.Unlock()
	}
	// Make sure the listener isn't already in the map
	if _, ok := r.servers[server.ID()]; ok {
		return fmt.Errorf("a server with an ID of %s already exists", server.ID())
	}
	// Add
	r.Lock()
	r.servers[server.ID()] = server
	r.Unlock()
	return nil
}

// SetOption updates the http.Server's configurable option with the provided value
func (r *Repository) SetOption(id uuid.UUID, option, value string) error {
	server, err := r.Server(id)
	if err != nil {
		return fmt.Errorf("pkg/servers/http/memory.SetOption(): %s", err)
	}
	r.Lock()
	defer r.Unlock()
	err = server.SetOption(option, value)
	if err != nil {
		return fmt.Errorf("pkg/servers/http/memory.SetOption(): %s", err)
	}
	r.servers[server.ID()] = server
	return nil
}

// Server returns a Server object for the passed in unique identifier
func (r *Repository) Server(id uuid.UUID) (http.Server, error) {
	r.Lock()
	defer r.Unlock()
	for _, s := range r.servers {
		if s.ID() == id {
			return s, nil
		}
	}
	return http.Server{}, fmt.Errorf("pkg/servers/http/memory.Get(): the server %s does not exist", id)
}

// Servers returns a list of all the stored Server objects
func (r *Repository) Servers() []http.Server {
	var found []http.Server
	r.Lock()
	defer r.Unlock()
	for _, s := range r.servers {
		found = append(found, s)
	}
	return found
}

// Remove deletes the Server object from the database
func (r *Repository) Remove(id uuid.UUID) {
	server, err := r.Server(id)
	if err == nil {
		r.Lock()
		defer r.Unlock()
		delete(serverMap, server.ID())
	}
}

func (r *Repository) Update(server http.Server) error {
	r.Lock()
	defer r.Unlock()
	_, ok := r.servers[server.ID()]
	if !ok {
		return fmt.Errorf("pkg/servers/http/memory/Update(): a server with ID %s does not exist and can't be updated", server.ID())
	}
	r.servers[server.ID()] = server
	return nil
}
