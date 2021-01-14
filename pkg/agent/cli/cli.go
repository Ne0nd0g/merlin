// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
package cli

import (
	// 3rd Party
	"github.com/fatih/color"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/core"
)

const (
	INFO    = 1
	NOTE    = 2
	WARN    = 3
	DEBUG   = 4
	SUCCESS = 5
)

// Message is used to print text to Standard Out
func Message(level int, message string) {
	switch level {
	case INFO:
		if core.Verbose {
			color.Cyan("[i]" + message)
		}
	case NOTE:
		if core.Verbose {
			color.Yellow("[-]" + message)
		}
	case WARN:
		if core.Verbose {
			color.Red("[!]" + message)
		}
	case DEBUG:
		if core.Debug {
			color.Red("[DEBUG]" + message)
		}
	case SUCCESS:
		if core.Verbose {
			color.Green("[+]" + message)
		}
	default:
		if core.Verbose {
			color.Red("[_-_]Invalid message level: " + message)
		}
	}
}
