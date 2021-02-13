// +build !linux
// +build !windows
// +build !darwin

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
	"fmt"
	"runtime"
)

// shell is used to execute a command on a host using the operating system's default shell
func shell(name string, args []string) (stdout string, stderr string) {
	return "", fmt.Sprintf("the default shell for the %s operating system is unknown, use the \"run\" command instead", runtime.GOOS)
}
