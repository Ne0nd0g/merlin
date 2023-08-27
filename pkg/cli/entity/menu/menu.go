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

package menu

type Menu int

const (
	// NONE is the default or zero value used when the menu is not set
	NONE Menu = iota
	ALLMENUS
	MAIN
	AGENT
	// LISTENER is for a specific, already instantiated, listener menu
	LISTENER
	// LISTENERS is for the top-level listeners menu
	LISTENERS
	// LISTENERSETUP is the menu used to configure listener options before creation
	LISTENERSETUP
	// MODULE is for a specific, already instantiated, module menu
	MODULE
	// MODULES is for the top-level module menu
	MODULES
)

func (m Menu) String() string {
	switch m {
	case NONE:
		return "none"
	case ALLMENUS:
		return "all"
	case MAIN:
		return "main"
	case AGENT:
		return "agent"
	case LISTENER:
		return "listener"
	case LISTENERS:
		return "listeners"
	case LISTENERSETUP:
		return "listenersetup"
	case MODULE:
		return "module"
	case MODULES:
		return "modules"
	default:
		return "unknown menu"
	}
}
