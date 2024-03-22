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

// Package memory is an in-memory database used to store and retrieve groups
package memory

import (
	// Standard
	"errors"
	"sync"

	//3rd Party
	"github.com/google/uuid"
)

var (
	ErrGroupNotFound = errors.New("pkg/group/memory: the group was not found in the repository")
)

// Repository is a structure that implements the group package's Repository interface
type Repository struct {
	sync.Mutex
	groups map[string][]uuid.UUID
}

// NewRepository is a factory that returns a structure that implements the group package's Repository interface
func NewRepository() *Repository {
	groups := make(map[string][]uuid.UUID)

	globalUUID, err := uuid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	if err == nil {
		groups["all"] = []uuid.UUID{globalUUID}
	}

	return &Repository{groups: groups}
}

// AddAgent will add the provided Agent ID to the provided group name. If the group name does not exist, it will be created.
func (r *Repository) AddAgent(group string, id uuid.UUID) error {
	agents, ok := r.groups[group]
	if !ok {
		// If the group doesn't exist, create it
		r.Lock()
		r.groups[group] = []uuid.UUID{id}
		r.Unlock()
		return nil
	}
	// See if the agent is already in the group
	for _, agent := range agents {
		if agent == id {
			return nil
		}
	}

	// Add the agent to the group's list
	r.Lock()
	r.groups[group] = append(agents, id)
	r.Unlock()
	return nil
}

// RemoveAgent removes an agent from a group
func (r *Repository) RemoveAgent(group string, id uuid.UUID) error {
	agents, ok := r.groups[group]
	if !ok {
		return ErrGroupNotFound
	}

	for i, agent := range agents {
		if id == agent {
			agents = append(agents[:i], agents[i+1:]...)
		}
	}

	r.Lock()
	r.groups[group] = agents
	r.Unlock()

	return nil
}

// Members returns a list of lists that contains all created groups and their Agent members
func (r *Repository) Members() (members map[string][]uuid.UUID) {
	r.Lock()
	members = r.groups
	r.Unlock()
	return
}

// Groups returns a list of all the created groups
func (r *Repository) Groups() (groups []string) {
	r.Lock()
	for group := range r.groups {
		groups = append(groups, group)
	}
	r.Unlock()
	return
}
