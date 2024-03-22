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

package smb

import "github.com/google/uuid"

// Repository is an interface to store and manage TCP listeners
type Repository interface {
	Add(listener Listener) error
	Exists(name string) bool
	List() func(string) []string
	Listeners() []Listener
	ListenerByID(id uuid.UUID) (Listener, error)
	ListenerByName(name string) (Listener, error)
	RemoveByID(id uuid.UUID) error
	SetOption(id uuid.UUID, option, value string) error
}
