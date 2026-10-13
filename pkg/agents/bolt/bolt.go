/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2026 Russel Van Tuyl

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

// Package bolt provides a bbolt-backed, write-through implementation of the
// agents.Repository interface so that Agent state survives a server restart.
//
// Reads are served from an in-memory map (identical semantics to the memory
// repository). Every mutation is written through to the bbolt database first
// and only committed to the in-memory map once the disk write succeeds, so the
// database is the source of truth and the two never diverge. On construction
// the repository reloads every persisted Agent back into memory.
//
// Serialization note: agents.Agent has only unexported fields, so it cannot be
// marshaled directly from outside the agents package. Instead each Agent's
// persistable state is copied into agentDTO via the type's public getters and
// rebuilt on load via agents.NewAgent plus the Update* setters. Two fields are
// intentionally not persisted:
//
//   - opaque (*opaque.Server): transient PAKE state that is nil once an agent
//     has authenticated (see Agent.ResetOPAQUE). An agent caught mid-handshake
//     by a restart simply re-registers, so it is reloaded as nil.
//   - log (*os.File): recreated by agents.NewAgent on load; nothing to persist.
//
// The per-agent secret IS persisted, since the server needs it to decrypt agent
// traffic after a restart.
//
// TODO(follow-up): a cleaner long-term fix is to give agents.Agent its own
// exported DTO / MarshalJSON so every persistence backend stops reaching through
// getters and setters. That touches the core type and is left to the maintainer.
package bolt

import (
	// Standard
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	// 3rd Party
	"github.com/google/uuid"
	"go.etcd.io/bbolt"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
)

var (
	// ErrAgentExists is returned when adding an Agent whose ID is already stored
	ErrAgentExists = errors.New("the agent already exists in the repository")
	// ErrAgentNotFound is returned when the requested Agent ID is not stored
	ErrAgentNotFound = errors.New("the agent was not found in the repository")
)

// bucketName is the bbolt bucket that holds the serialized Agent records keyed by Agent ID
var bucketName = []byte("agents")

// Repository is a bbolt-backed implementation of agents.Repository. It keeps an
// in-memory copy of every Agent for fast reads and writes each change through to
// the database.
type Repository struct {
	sync.Mutex
	agents map[uuid.UUID]agents.Agent
	db     *bbolt.DB
}

// compile-time assertion that Repository satisfies the domain interface
var _ agents.Repository = (*Repository)(nil)

// agentDTO is the on-disk representation of an Agent. Every field is exported so
// it can be JSON-encoded; opaque and the log file handle are deliberately omitted
// (see the package comment).
type agentDTO struct {
	ID            uuid.UUID
	Alive         bool
	Authenticated bool
	Build         agents.Build
	Host          agents.Host
	Process       agents.Process
	Comms         agents.Comms
	Initial       time.Time
	Checkin       time.Time
	LinkedAgents  []uuid.UUID
	Listener      uuid.UUID
	Secret        []byte
	Note          string
}

// NewRepository opens (creating if necessary) the bbolt database at path, ensures
// the agents bucket exists, reloads every persisted Agent into memory, and returns
// the ready-to-use Repository. Call Close when finished to release the file lock.
func NewRepository(path string) (*Repository, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("pkg/agents/bolt.NewRepository(): there was an error opening the database %q: %w", path, err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pkg/agents/bolt.NewRepository(): there was an error creating the %q bucket: %w", bucketName, err)
	}

	r := &Repository{
		agents: make(map[uuid.UUID]agents.Agent),
		db:     db,
	}

	if err = r.load(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return r, nil
}

// Close releases the underlying database and its file lock.
func (r *Repository) Close() error {
	return r.db.Close()
}

// load reads every persisted Agent from the database and rebuilds it in the
// in-memory map. It is called once during construction.
func (r *Repository) load() error {
	r.Lock()
	defer r.Unlock()
	return r.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var dto agentDTO
			if err := json.Unmarshal(v, &dto); err != nil {
				return fmt.Errorf("pkg/agents/bolt.load(): there was an error decoding agent %x: %w", k, err)
			}
			agent, err := rebuild(dto)
			if err != nil {
				return err
			}
			r.agents[dto.ID] = agent
			return nil
		})
	})
}

// Add stores a new Agent. It returns ErrAgentExists if the ID is already present.
func (r *Repository) Add(agent agents.Agent) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.agents[agent.ID()]; ok {
		return ErrAgentExists
	}
	if err := r.persistLocked(agent); err != nil {
		return err
	}
	r.agents[agent.ID()] = agent
	return nil
}

// Exists reports whether an Agent with the provided ID is stored.
func (r *Repository) Exists(id uuid.UUID) bool {
	r.Lock()
	defer r.Unlock()
	_, ok := r.agents[id]
	return ok
}

// Get returns a COPY of the stored Agent. Mutating the copy does not update the
// repository; use the Update* methods for that.
func (r *Repository) Get(id uuid.UUID) (agents.Agent, error) {
	r.Lock()
	defer r.Unlock()
	agent, ok := r.agents[id]
	if !ok {
		return agents.Agent{}, ErrAgentNotFound
	}
	return agent, nil
}

// GetAll returns a copy of every stored Agent.
func (r *Repository) GetAll() (all []agents.Agent) {
	r.Lock()
	defer r.Unlock()
	for _, agent := range r.agents {
		all = append(all, agent)
	}
	return
}

// Update replaces the stored Agent with the one provided.
func (r *Repository) Update(agent agents.Agent) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.agents[agent.ID()]; !ok {
		return ErrAgentNotFound
	}
	if err := r.persistLocked(agent); err != nil {
		return err
	}
	r.agents[agent.ID()] = agent
	return nil
}

// Remove deletes the Agent from both the database and the in-memory map.
func (r *Repository) Remove(id uuid.UUID) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.agents[id]; !ok {
		return ErrAgentNotFound
	}
	err := r.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key(id))
	})
	if err != nil {
		return fmt.Errorf("pkg/agents/bolt.Remove(): there was an error deleting agent %s: %w", id, err)
	}
	delete(r.agents, id)
	return nil
}

// Log writes the message to the Agent's log file. It changes no persisted state,
// so nothing is written to the database.
func (r *Repository) Log(id uuid.UUID, message string) error {
	r.Lock()
	defer r.Unlock()
	agent, ok := r.agents[id]
	if !ok {
		return ErrAgentNotFound
	}
	agent.Log(message)
	return nil
}

// SetSecret updates the Agent's symmetric secret key.
func (r *Repository) SetSecret(id uuid.UUID, secret []byte) error {
	return r.mutate(id, func(a *agents.Agent) { a.SetSecret(secret) })
}

// AddLinkedAgent records a child (peer-to-peer) Agent under the given parent.
func (r *Repository) AddLinkedAgent(id uuid.UUID, link uuid.UUID) error {
	return r.mutate(id, func(a *agents.Agent) { a.AddLink(link) })
}

// RemoveLinkedAgent removes a child Agent from the given parent's link list.
func (r *Repository) RemoveLinkedAgent(id uuid.UUID, link uuid.UUID) error {
	return r.mutate(id, func(a *agents.Agent) { a.RemoveLink(link) })
}

// UpdateAlive updates the Agent's alive status.
func (r *Repository) UpdateAlive(id uuid.UUID, alive bool) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateAlive(alive) })
}

// UpdateAuthenticated updates the Agent's authenticated status.
func (r *Repository) UpdateAuthenticated(id uuid.UUID, authenticated bool) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateAuthenticated(authenticated) })
}

// UpdateBuild updates the Agent's Build entity.
func (r *Repository) UpdateBuild(id uuid.UUID, build agents.Build) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateBuild(build) })
}

// UpdateComms updates the Agent's Comms entity.
func (r *Repository) UpdateComms(id uuid.UUID, comms agents.Comms) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateComms(comms) })
}

// UpdateHost updates the Agent's Host entity.
func (r *Repository) UpdateHost(id uuid.UUID, host agents.Host) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateHost(host) })
}

// UpdateInitial updates the timestamp for when the Agent was first seen.
func (r *Repository) UpdateInitial(id uuid.UUID, t time.Time) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateInitial(t) })
}

// UpdateListener updates the listener ID the Agent is associated with.
func (r *Repository) UpdateListener(id, listener uuid.UUID) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateListener(listener) })
}

// UpdateProcess updates the Agent's Process entity.
func (r *Repository) UpdateProcess(id uuid.UUID, process agents.Process) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateProcess(process) })
}

// UpdateNote updates the Agent's operator note.
func (r *Repository) UpdateNote(id uuid.UUID, note string) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateNote(note) })
}

// UpdateStatusCheckin updates the timestamp for when the Agent last checked in.
func (r *Repository) UpdateStatusCheckin(id uuid.UUID, t time.Time) error {
	return r.mutate(id, func(a *agents.Agent) { a.UpdateStatusCheckin(t) })
}

// mutate applies fn to a copy of the stored Agent, persists the result, and only
// then commits it to the in-memory map, keeping disk and memory consistent.
func (r *Repository) mutate(id uuid.UUID, fn func(a *agents.Agent)) error {
	r.Lock()
	defer r.Unlock()
	agent, ok := r.agents[id]
	if !ok {
		return ErrAgentNotFound
	}
	fn(&agent)
	if err := r.persistLocked(agent); err != nil {
		return err
	}
	r.agents[id] = agent
	return nil
}

// persistLocked writes the Agent's serializable state to the database. The caller
// must hold r's lock.
func (r *Repository) persistLocked(agent agents.Agent) error {
	blob, err := json.Marshal(toDTO(agent))
	if err != nil {
		return fmt.Errorf("pkg/agents/bolt.persistLocked(): there was an error encoding agent %s: %w", agent.ID(), err)
	}
	err = r.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put(key(agent.ID()), blob)
	})
	if err != nil {
		return fmt.Errorf("pkg/agents/bolt.persistLocked(): there was an error writing agent %s: %w", agent.ID(), err)
	}
	return nil
}

// key returns the bbolt key for an Agent ID (its 16-byte canonical form).
func key(id uuid.UUID) []byte {
	return id[:]
}

// toDTO copies an Agent's persistable state out through its public getters.
func toDTO(a agents.Agent) agentDTO {
	return agentDTO{
		ID:            a.ID(),
		Alive:         a.Alive(),
		Authenticated: a.Authenticated(),
		Build:         a.Build(),
		Host:          a.Host(),
		Process:       a.Process(),
		Comms:         a.Comms(),
		Initial:       a.Initial(),
		Checkin:       a.StatusCheckin(),
		LinkedAgents:  a.Links(),
		Listener:      a.Listener(),
		Secret:        a.Secret(),
		Note:          a.Note(),
	}
}

// rebuild reconstructs an Agent from its DTO using only the agents package's
// public API. opaque is restored as nil (see the package comment).
func rebuild(dto agentDTO) (agents.Agent, error) {
	agent, err := agents.NewAgent(dto.ID, dto.Secret, nil, dto.Initial)
	if err != nil {
		return agent, fmt.Errorf("pkg/agents/bolt.rebuild(): there was an error recreating agent %s: %w", dto.ID, err)
	}
	agent.UpdateAlive(dto.Alive)
	agent.UpdateAuthenticated(dto.Authenticated)
	agent.UpdateBuild(dto.Build)
	agent.UpdateHost(dto.Host)
	agent.UpdateProcess(dto.Process)
	agent.UpdateComms(dto.Comms)
	agent.UpdateListener(dto.Listener)
	agent.UpdateStatusCheckin(dto.Checkin)
	agent.UpdateNote(dto.Note)
	for _, link := range dto.LinkedAgents {
		agent.AddLink(link)
	}
	return agent, nil
}
