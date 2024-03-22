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
	"fmt"
	"github.com/Ne0nd0g/merlin/v2/pkg/client"
	"github.com/google/uuid"
	"sync"
)

type Repository struct {
	clients map[uuid.UUID]client.Client
	sync.Mutex
}

var repo *Repository

func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			clients: make(map[uuid.UUID]client.Client),
		}
	}
	return repo
}

func (r *Repository) Add(client client.Client) {
	r.Lock()
	r.clients[client.ID()] = client
	r.Unlock()
}

func (r *Repository) Get(id uuid.UUID) (client client.Client, err error) {
	r.Lock()
	defer r.Unlock()
	var ok bool
	client, ok = r.clients[id]
	if !ok {
		err = fmt.Errorf("pkg/client/memory: client with id %s was not found in the repository", id)
	}
	return
}

func (r *Repository) GetAll() (clients []client.Client) {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.clients {
		clients = append(clients, c)
	}
	return
}
