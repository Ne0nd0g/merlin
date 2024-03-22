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

package agents

import (
	"github.com/google/uuid"
	"time"
)

// Repository is an interface used to add, get, or update Agents from a data source
type Repository interface {
	Add(agent Agent) error
	Get(id uuid.UUID) (Agent, error)
	GetAll() (agents []Agent)
	Remove(id uuid.UUID) error
	Log(id uuid.UUID, message string) error
	Update(agent Agent) error
	UpdateAlive(id uuid.UUID, alive bool) error
	UpdateAuthenticated(id uuid.UUID, authenticated bool) error
	UpdateBuild(id uuid.UUID, build Build) error
	UpdateComms(id uuid.UUID, comms Comms) error
	UpdateHost(id uuid.UUID, host Host) error
	UpdateInitial(id uuid.UUID, t time.Time) (err error)
	UpdateListener(id, listener uuid.UUID) error
	UpdateProcess(id uuid.UUID, process Process) error
	UpdateNote(id uuid.UUID, note string) error
	UpdateStatusCheckin(id uuid.UUID, t time.Time) (err error)
	AddLinkedAgent(id uuid.UUID, link uuid.UUID) error
	RemoveLinkedAgent(id uuid.UUID, link uuid.UUID) error
}
