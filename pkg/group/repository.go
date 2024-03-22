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

// Package group manages Agent groupings so that tasks can be issued against a group
package group

import "github.com/google/uuid"

// Repository is an interface used to add, get, or update groups from a data source
type Repository interface {
	AddAgent(group string, id uuid.UUID) error
	Groups() (groups []string)
	Members() (members map[string][]uuid.UUID)
	RemoveAgent(group string, id uuid.UUID) error
}
