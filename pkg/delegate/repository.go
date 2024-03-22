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

// Package delegate provides a repository to store and retrieve delegate Base messages that have been encoded/encrypted
// into a byte slice using the Agent's transforms and keys
package delegate

import "github.com/google/uuid"

// Repository is an interface to store and retrieve data
type Repository interface {
	// Add data to the in-memory map for the provided Agent ID
	Add(id uuid.UUID, data []byte)
	// Get return data from the in-memory map for the provided Agent ID
	Get(id uuid.UUID) [][]byte
}
