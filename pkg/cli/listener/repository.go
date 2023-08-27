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

package listener

import (
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/listener"
	uuid "github.com/satori/go.uuid"
)

type Repository interface {
	Add(listener listener.Listener)
	Get(id uuid.UUID) (*listener.Listener, error)
	Remove(id uuid.UUID)
	ServerID(id uuid.UUID, serverID uuid.UUID) error
	Update(id uuid.UUID, options map[string]string) error
}
