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

package os

import "strings"

type OS int

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

func FromString(operatingSystem string) OS {
	switch strings.ToLower(operatingSystem) {
	case "local":
		return LOCAL
	case "all":
		return ALL
	case "windows":
		return WINDOWS
	case "linux":
		return LINUX
	case "macos":
		return MACOS
	case "debian":
		return DEBIAN
	default:
		return UNDEFINED
	}
}
