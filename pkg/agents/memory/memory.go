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
	// Standard
	"errors"
	"sync"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
)

var (
	ErrAgentExists   = errors.New("the agent already exists in the repository")
	ErrAgentNotFound = errors.New("the agent was not found in the repository")
)

// Repository structure implements an in-memory database that holds a map of agent's the server communicates with
type Repository struct {
	// Don't use pointers because this is map is the source and should only be modified here in the repository
	agents map[uuid.UUID]agents.Agent
	sync.Mutex
}

// repo is the in-memory database
var repo = &Repository{agents: make(map[uuid.UUID]agents.Agent)}

// NewRepository creates and returns a Repository structure that contains an in-memory map of agents
func NewRepository() *Repository {
	return repo
}

// Add locks the in-memory database and adds Agent structures to the map
func (r *Repository) Add(agent agents.Agent) error {
	if !r.Exists(agent.ID()) {
		r.Lock()
		r.agents[agent.ID()] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentExists
}

// AddLinkedAgent updates the Agent's linkedAgents list the contains all child agents for which it is the parent
func (r *Repository) AddLinkedAgent(id uuid.UUID, link uuid.UUID) error {
	agent, err := r.Get(id)
	if err != nil {
		return err
	}
	agent.AddLink(link)
	r.Lock()
	r.agents[id] = agent
	r.Unlock()
	return nil
}

// Exists check's to see if the Agent is in the repository
func (r *Repository) Exists(id uuid.UUID) bool {
	for a := range r.agents {
		if a == id {
			return true
		}
	}
	return false
}

// Get returns a COPY of the Agent entity. The caller should not try to modify the copy as it won't be updated
// in the repository
func (r *Repository) Get(id uuid.UUID) (agents.Agent, error) {
	agent, ok := r.agents[id]
	if ok {
		return agent, nil
	}
	return agents.Agent{}, ErrAgentNotFound
}

// GetAll returns a list of all Agents in the repository
func (r *Repository) GetAll() (agents []agents.Agent) {
	r.Lock()
	for _, agent := range r.agents {
		agents = append(agents, agent)
	}
	r.Unlock()
	return
}

// Remove deletes the agent from the repository
func (r *Repository) Remove(id uuid.UUID) (err error) {
	if r.Exists(id) {
		r.Lock()
		delete(r.agents, id)
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// RemoveLinkedAgent removed the provided link the Agent's linkedAgents list the contains all child agents for which it is the parent
func (r *Repository) RemoveLinkedAgent(id uuid.UUID, link uuid.UUID) error {
	agent, err := r.Get(id)
	if err != nil {
		return err
	}
	agent.RemoveLink(link)
	r.Lock()
	r.agents[id] = agent
	r.Unlock()
	return nil
}

// SetSecret updates the agent's secret key, typically derived once authentication has completed and per-agent key has
// been established.
func (r *Repository) SetSecret(id uuid.UUID, secret []byte) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.SetSecret(secret)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// Update replaces the Agent in the repository with the one provided in the function call
func (r *Repository) Update(agent agents.Agent) error {
	if r.Exists(agent.ID()) {
		r.Lock()
		r.agents[agent.ID()] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateAlive updates the Agent's alive field to indicate if it is actively in use or not
func (r *Repository) UpdateAlive(id uuid.UUID, alive bool) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateAlive(alive)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateAuthenticated updates that Agent's authenticated field, typically once authentication has completed
func (r *Repository) UpdateAuthenticated(id uuid.UUID, authenticated bool) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateAuthenticated(authenticated)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateBuild updates the Agent's build field with the provided Build entity structure
func (r *Repository) UpdateBuild(id uuid.UUID, build agents.Build) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateBuild(build)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateComms updates the Agent's comms field with the provided Comms entity structure
func (r *Repository) UpdateComms(id uuid.UUID, comms agents.Comms) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateComms(comms)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateHost updates the Agent's host field with the provided Host entity structure
func (r *Repository) UpdateHost(id uuid.UUID, host agents.Host) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateHost(host)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateInitial updates the Agent's initial field with the provided timestamp
func (r *Repository) UpdateInitial(id uuid.UUID, t time.Time) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateInitial(t)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateListener updates the ID of the listener the Agent is associated with
func (r *Repository) UpdateListener(id, listener uuid.UUID) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateListener(listener)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateProcess updates the Agent's process field with the provided Process entity structure
func (r *Repository) UpdateProcess(id uuid.UUID, process agents.Process) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateProcess(process)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateNote updates the Agent's note field with the provided string
func (r *Repository) UpdateNote(id uuid.UUID, note string) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateNote(note)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// UpdateStatusCheckin updates the Agent's last checkin field with the provided timestamp
func (r *Repository) UpdateStatusCheckin(id uuid.UUID, t time.Time) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.UpdateStatusCheckin(t)
		r.agents[id] = agent
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}

// Log writes the provided message to the Agent's log file
func (r *Repository) Log(id uuid.UUID, message string) error {
	if r.Exists(id) {
		r.Lock()
		agent := r.agents[id]
		agent.Log(message)
		r.Unlock()
		return nil
	}
	return ErrAgentNotFound
}
