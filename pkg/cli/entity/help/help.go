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

package help

// Help captures the pertitenent pieces of information for a CLI command
type Help struct {
	description string // description is a single sentence description of the command
	example     string // example is an example of how to use the command
	notes       string // notes returns any additional information that is relevant to understanding the command
	usage       string // usage returns the command's required and optional arguments along with exclusive groupings. Style guide for usage https://developers.google.com/style/code-syntax
}

// NewHelp is a factory to build and return a Help structure
func NewHelp(description, example, notes, usage string) Help {
	return Help{
		description: description,
		example:     example,
		notes:       notes,
		usage:       usage,
	}
}

// Description returns a single sentence description of the command
func (h *Help) Description() string {
	return h.description
}

// Example returns an example of running the command
func (h *Help) Example() string {
	return h.example
}

// Notes returns any additional information that is relevant to understanding the command
func (h *Help) Notes() string {
	return h.notes
}

// String returns the command's usage as the required and optional arguments along with exclusive groupings
func (h *Help) String() string {
	return h.usage
}

// Usage returns the command's required and optional arguments along with exclusive groupings
func (h *Help) Usage() string {
	return h.usage
}
