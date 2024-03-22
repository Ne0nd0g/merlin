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

// Package http holds the HTTP servers to send/receive Agent messages
package http

import "github.com/google/uuid"

// Repository is an interface to store and manage HTTP servers
type Repository interface {
	Add(server Server) error
	Remove(id uuid.UUID)
	Server(id uuid.UUID) (Server, error)
	Servers() []Server
	SetOption(id uuid.UUID, option, value string) error
	Update(server Server) error
}
