// +build !linux

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

package commands

import (
	// Standard
	"fmt"
	"runtime"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// Memfd places a linux executable file in-memory, executes it, and returns the results
// Uses the linux memfd_create API call to create an anonymous file
// https://man7.org/linux/man-pages/man2/memfd_create.2.html
// http://manpages.ubuntu.com/manpages/bionic/man2/memfd_create.2.html
func Memfd(cmd jobs.Command) (result jobs.Results) {
	result.Stderr = fmt.Sprintf("the memfd command is not implemented for the %s operating system", runtime.GOOS)
	return
}
