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

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// ExecuteCommand runs the provided input program and arguments, returning results in a message base
func ExecuteCommand(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for executeCommand function: %+v", cmd))
	cli.Message(cli.SUCCESS, fmt.Sprintf("Executing command: %s %s", cmd.Command, cmd.Args))

	var results jobs.Results
	if cmd.Command == "shell" {
		results.Stdout, results.Stderr = shell(cmd.Args)
	} else {
		results.Stdout, results.Stderr = executeCommand(cmd.Command, cmd.Args)
	}

	if results.Stderr != "" {
		cli.Message(cli.WARN, fmt.Sprintf("There was an error executing the command: %s %s", cmd.Command, cmd.Args))
		cli.Message(cli.SUCCESS, results.Stdout)
		cli.Message(cli.WARN, fmt.Sprintf("Error: %s", results.Stderr))

	} else {
		cli.Message(cli.SUCCESS, fmt.Sprintf("Command output:\r\n\r\n%s", results.Stdout))
	}

	return results
}
