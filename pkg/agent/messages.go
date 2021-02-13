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

package agent

import (
	// Standard
	"fmt"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// messageHandler processes an input message from the server and adds it to the job channel for processing by the agent
func (a *Agent) messageHandler(m messages.Base) {
	cli.Message(cli.DEBUG, "Entering into agent.messageHandler function")
	cli.Message(cli.SUCCESS, fmt.Sprintf("%s message type received!", messages.String(m.Type)))

	if m.ID != a.ID {
		cli.Message(cli.WARN, fmt.Sprintf("Input message was not for this agent (%s):\r\n%+v", a.ID, m))
	}

	var result jobs.Results
	switch m.Type {
	case messages.JOBS:
		a.jobHandler(m.Payload.([]jobs.Job))
	case messages.IDLE:
		cli.Message(cli.NOTE, "Received idle command, doing nothing")
	case messages.OPAQUE:
		if m.Payload.(opaque.Opaque).Type == opaque.ReAuthenticate {
			cli.Message(cli.NOTE, "Received re-authentication request")
			// Re-authenticate, but do not re-register
			msg, err := a.Client.Auth("opaque", false)
			if err != nil {
				a.FailedCheckin++
				result.Stderr = err.Error()
				jobsOut <- jobs.Job{
					AgentID: a.ID,
					Type:    jobs.RESULT,
					Payload: result,
				}
			}
			a.messageHandler(msg)
		}
	default:
		result.Stderr = fmt.Sprintf("%s is not a valid message type", messages.String(m.Type))
		jobsOut <- jobs.Job{
			AgentID: m.ID,
			Type:    jobs.RESULT,
			Payload: result,
		}
	}
	cli.Message(cli.DEBUG, "Leaving agent.messageHandler function without error")
}
