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

package commands

import (
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	uuid "github.com/satori/go.uuid"
)

// os structure constants
const (
	// UNDEFINED represents commands that are not defined because zero is the default value for int
	UNDEFINED OS = iota
	// LOCAL represents commands that are only used locally on the CLI and not sent to an Agent
	LOCAL
	// ALL represents commands that can be executed by Agents on any operating system
	ALL
	// WINDOWS represents commands that can be executed by Agents on Windows operating systems
	WINDOWS
	// LINUX represents commands that can be executed by Agents on Linux operating systems
	LINUX
	// MACOS represents commands that can be executed by Agents on macOS operating systems
	MACOS
	// DEBIAN represents commands that can be executed by Agents on Debian operating systems
	DEBIAN
)

type OS int

// String returns the string representation of the os type
func (o OS) String() string {
	switch o {
	case UNDEFINED:
		return "undefined operating system"
	case LOCAL:
		return "local"
	case ALL:
		return "all"
	case WINDOWS:
		return "Windows"
	case LINUX:
		return "Linux"
	case MACOS:
		return "macOS"
	case DEBIAN:
		return "Debian"
	default:
		return "unknown operating system"
	}
}

// API is the Merlin API function that is called when a command is executed
type API func(agentID uuid.UUID, Args []string) messages.UserMessage

type Help struct {
	Description string // Description is a single sentence description of the command
	Example     string // Example is an example of how to use the command
	Notes       string
	Usage       string
}

type Menu int

const (
	ALLMENUS Menu = iota
	MAIN
	AGENT
	LISTENER
	MODULE
)

// String returns the string representation of the menu type
func (m Menu) String() string {
	switch m {
	case ALLMENUS:
		return "all"
	case MAIN:
		return "main"
	case AGENT:
		return "agent"
	case LISTENER:
		return "listener"
	case MODULE:
		return "module"
	default:
		return "unknown menu"
	}
}
