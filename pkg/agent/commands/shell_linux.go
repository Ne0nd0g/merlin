// +build linux

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

import "os/exec"

// shell is used to execute a command on a host using the operating system's default shell
func shell(args []string) (stdout string, stderr string) {
	cmd := exec.Command("/bin/sh", append([]string{"-c"}, args...)...) // #nosec G204

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}
