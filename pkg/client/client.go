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

// Package client contains code for working with Merlin Command Line Interface (CLI) clients connected over gRPC
package client

import "github.com/google/uuid"

type Client struct {
	id uuid.UUID
}

func NewClient() Client {
	return Client{id: uuid.New()}
}

func NewClientWithID(id uuid.UUID) Client {
	return Client{id: id}
}

func (c Client) ID() uuid.UUID {
	return c.id
}
